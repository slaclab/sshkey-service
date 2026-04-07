# 004 — Redis Key Fingerprint Validation

**Status:** 🔍 Reviewed  
**Severity:** LOW (revised from MEDIUM — see Threat Model)  
**Category:** Injection / Defence-in-depth

---

## Problem & Goal

**Problem:** Caller-supplied fingerprints in URL path parameters (`/destroy/{username}/{finger_print}`,
`/inactivate/...`, `/refresh/...`, `/notes/...`) are embedded directly into Redis key strings with
no validation:

```python
key = f"user:{username}:{finger_print}"
await redis.hgetall(key)
```

If a fingerprint contains `:`, the Redis key gains extra segments (`user:alice:SHA256:foo:bar`
instead of `user:alice:SHA256:foo`), breaking the three-segment structural assumption that
`scan_iter("user:{username}:*")` depends on.

**Goal:** All fingerprint values — both computed during upload and supplied by callers — are
validated against a strict allowlist regex before any Redis operation.

**Success metric:** A request with a fingerprint containing `:`, `*`, `?`, `[`, or other
characters outside the allowlist is rejected with HTTP 400 before any Redis operation occurs.

**Out of scope:**
- Changing the Redis key schema or separator character
- Validating `username` path parameters (separate concern)

**Constraints:**
- Must not reject legitimately formatted SHA256 fingerprints (the only format this service produces)
- Backward-compatible: stored keys already use `.` in place of `/` and `+`

---

## Threat Model

This section grounds the severity downgrade and clarifies what is and is not exploitable.

### What the Ingress already constrains

The `slac-ssh-mfa-ingress-modify` Ingress path regex is:
```
/(destroy|inactivate|refresh|notes)/(\w+)/(SHA256:[\w.]+)
```

`[\w.]` matches `[A-Za-z0-9_.]` only. Characters like `:`, `*`, `?`, `[` are **not** matched,
so any request containing them is rejected by nginx with 404 before it reaches the app.

This means:
- An **external** attacker cannot supply a malformed fingerprint through the standard HTTPS path
- The injection surface is limited to **internal** callers that bypass nginx (same cluster
  access concern as #001) or to future code changes that loosen the path regex

### What remains at risk

| Vector | Exploitable? | Why |
|---|---|---|
| External HTTPS request with `:` in fingerprint | ❌ No | nginx path regex rejects it |
| Internal pod calling service directly with `:` in fingerprint | ✅ Yes | No NetworkPolicy (see #001); app has no validation |
| Upload path (`determine_public_key`) | ❌ No | Fingerprint is computed by paramiko, not caller-supplied |
| Future Ingress with looser path regex | ✅ Would be | No app-layer backstop currently |

### Relationship to #001

Fixing #001 (NetworkPolicy) closes the internal cluster attack surface that makes this
exploitable today. This fix (#004) provides defence-in-depth: the app validates fingerprints
regardless of how the request arrived. It also protects against a future Ingress misconfiguration
that accidentally widens the path pattern.

### Redis injection severity

Redis treats key names as arbitrary byte strings — there is no command injection in the SQL
sense. The actual harm is structural: a key named `user:alice:SHA256:foo:bar` would:
- Be found by `scan_iter("user:alice:*")` (extra match, minor data leak in list responses)
- Not be found by `redis.hgetall("user:alice:SHA256:foo")` (lookup miss, 404 response)
- Not corrupt existing valid keys

It is a correctness bug and a latent data-integrity risk, not an immediate data-exfiltration
vector.

---

## Requirements

### Functional Requirements

```
FR-1: A module-level _FINGERPRINT_RE regex is defined that matches only valid cleaned
      SHA256 fingerprints as produced and stored by this service.
FR-2: A validate_fingerprint(fp: str) -> str helper raises HTTPException(400) for any
      fingerprint that does not match _FINGERPRINT_RE.
FR-3: validate_fingerprint() is called in determine_public_key immediately after the
      cleaning step, before the Redis duplicate-check.
FR-4: validate_fingerprint() is called at the top of destroy_user_keypair,
      inactivate_user_keypair, refresh_user_keypair, and update_user_notes,
      BEFORE the opening logger.info() call, before any blacklist check, and
      before any Redis operation. (All four endpoints currently log the raw
      finger_print in their first line — that log call must come after
      validation, or the log line must be removed/deferred.)
FR-5: The 400 error message does not echo back the raw fingerprint value (avoid
      reflecting potentially hostile input in responses). This applies only to the
      new 400 raised by validate_fingerprint(). Existing 404 messages that echo
      {finger_print} are exempt: they are only reached after validate_fingerprint()
      has already confirmed the value is within the safe allowlist character set.
```

### Non-Functional Requirements

```
NFR-1: The regex check adds negligible overhead (< 0.1 ms per request).
NFR-2: No new dependencies required.
NFR-3: All existing valid SHA256 fingerprints produced by paramiko pass the regex.
```

### Acceptance Criteria

```
AC-1: Given a valid cleaned SHA256 fingerprint (e.g. "SHA256:uNiVztksCsDhcc0u9e8BujQ..."),
      validate_fingerprint() returns it unchanged.
AC-2: Given a fingerprint containing ":" beyond the SHA256 prefix
      (e.g. "SHA256:foo:bar"), validate_fingerprint() raises HTTPException(400).
AC-3: Given a fingerprint containing "*" or "?", validate_fingerprint() raises HTTPException(400).
AC-4: Given an empty string, validate_fingerprint() raises HTTPException(400).
AC-5: Given a raw (uncleaned) SHA256 fingerprint containing "/" or "+",
      validate_fingerprint() raises HTTPException(400) — raw fingerprints must be
      cleaned before validation.
AC-6: The 400 detail message does not contain the raw fingerprint value.
AC-7: Calling POST /upload with a key that produces a valid fingerprint succeeds (no regression).
AC-8: Calling DELETE /destroy with a fingerprint containing ":" returns 400 (not 404).
```

---

## Architecture

### Valid Fingerprint Format

OpenSSH SHA256 fingerprints have the form `SHA256:<base64-without-padding>`. After the service's
cleaning step (`/`→`.`, `+`→`.`, `rstrip('=')`), the character set is:

```
SHA256:[A-Za-z0-9.]{43}
```

The base64 body is always 43 characters (256-bit hash → 32 bytes → 43 base64 chars without
padding). The regex should enforce this exactly rather than using a loose range.

```python
import re

# SHA256: prefix + exactly 43 chars from the post-cleaning alphabet [A-Za-z0-9.]
# 43 = ceil(32 * 4/3) with padding stripped — holds for ALL key types (RSA, Ed25519,
# ECDSA) because SHA256 always produces 32 bytes regardless of the key type.
#
# Anchoring: re.match() anchors at the START of the string by default.
# The $ in the pattern anchors at the END. Together they are equivalent to
# re.fullmatch(r'SHA256:[A-Za-z0-9.]{43}', fp). If $ is ever removed, re.match
# alone would allow trailing garbage — keep both.
_FINGERPRINT_RE = re.compile(r'^SHA256:[A-Za-z0-9.]{43}$')

def validate_fingerprint(fp: str) -> str:
    """Validate a fingerprint against the SHA256 allowlist.

    Raises HTTPException(400) if the fingerprint does not match.
    Returns the fingerprint unchanged if valid.

    Note: fingerprint must already be cleaned (/ and + replaced with .)
    before calling this function.

    IMPORTANT: Call this before any logger.info() that would log the raw
    fingerprint value, to prevent log injection from hostile internal callers.
    """
    if not _FINGERPRINT_RE.match(fp):
        raise HTTPException(
            status_code=400,
            detail="Invalid fingerprint format. Expected SHA256 fingerprint."
        )
    return fp
```

### Call sites (5 locations in app.py)

```
determine_public_key() — line ~473
  finger_print = found.fingerprint.rstrip('=').replace('/','.').replace('+','.')
  finger_print = validate_fingerprint(finger_print)   ← ADD HERE
  return finger_print, found

destroy_user_keypair() — line ~608
  finger_print = validate_fingerprint(finger_print)   ← ADD BEFORE logger.info and before hgetall
  logger.info(f"Destroying SSH key pair for user: {username} with fingerprint: {finger_print}")
  item = await redis.hgetall(f"user:{username}:{finger_print}")

inactivate_user_keypair() — line ~623
  finger_print = validate_fingerprint(finger_print)   ← ADD BEFORE logger.info and before blacklist check
  logger.info(f"Invalidate SSH key pair for user: {username} with fingerprint: {finger_print}")
  with blacklist_lock: ...

refresh_user_keypair() — line ~656
  finger_print = validate_fingerprint(finger_print)   ← ADD BEFORE logger.info and before blacklist check
  logger.info(f"Refreshing SSH key pair for user: {username} with fingerprint: {finger_print}")
  with blacklist_lock: ...

update_user_notes() — line ~727
  finger_print = validate_fingerprint(finger_print)   ← ADD BEFORE logger.info and before blacklist check
  logger.info(f"Updating user notes for SSH key pair for user: {username} with fingerprint: {finger_print}")
  with blacklist_lock: ...
```

### No Migration Required — additive change

`validate_fingerprint()` only adds a rejection path for malformed input. All existing stored
fingerprints were produced by the cleaning step and will pass the regex. No Redis data changes.

---

## ADRs

### ADR-001: Allowlist regex with exact length vs. loose range

**Status:** Accepted  
**Date:** 2026-04-07

**Context:** The task file proposed `{40,60}` as the length range. SHA256 base64 without
padding is always exactly 43 characters. A loose range admits inputs that can never be valid
fingerprints.

**Decision:** Use `{43}` exactly. If paramiko ever changes its output format, the failure
is an explicit 400 (visible) rather than a silently accepted malformed key.

**Consequences:** If a future OpenSSH or paramiko version changes fingerprint length (very
unlikely for SHA256), the regex will need updating. This is a feature, not a bug.

---

### ADR-002: Validate at call site vs. FastAPI path validator (Annotated / Path)

**Status:** Accepted  
**Date:** 2026-04-07

**Context:** FastAPI supports annotating path parameters with `Annotated[str, Path(pattern=...)]`
which validates at the routing layer and returns a clean 422. This would be more idiomatic.

| Option | Pros | Cons |
|---|---|---|
| `validate_fingerprint()` helper | Consistent with existing `_parse_admins` pattern; reusable in upload path | Slightly more verbose; 400 not 422 |
| `Annotated[str, Path(pattern=...)]` | Idiomatic FastAPI; framework handles it | Cannot reuse in `determine_public_key` (not a path param); returns 422 instead of 400 |

**Decision:** `validate_fingerprint()` helper. It can be called in both path-param endpoints
and in the upload's `determine_public_key`, providing a single validation point. Consistency
with the codebase's existing explicit-validation style (`_parse_admins`) outweighs the
idiomatic FastAPI argument.

**Consequences:** Returns HTTP 400 (not 422) for invalid fingerprints from path params. This
is consistent with other validation errors in the codebase (e.g. invalid key format → 400).

---

## Trade-offs

```
Choice: Exact length {43} vs. range {40,60}
  + Exact: rejects all inputs that can't be valid SHA256 fingerprints
  - Exact: breaks if fingerprint format ever changes (deliberate — fail visibly)
  Decision: {43} exact.

Choice: Include "+" and "/" in the allowlist vs. require pre-cleaning
  + Including them: accepts uncleaned fingerprints from callers
  - Including them: callers could supply raw base64 that bypasses the cleaning step,
    creating inconsistency between stored and looked-up keys (lookup misses)
  Decision: Require pre-cleaning. The upload path always cleans; callers must supply
            the same cleaned format they received from the upload response.

Choice: Reflect fingerprint in error message vs. generic message
  + Reflecting: easier to debug for legitimate callers
  - Reflecting: reflects potentially hostile input back to attacker (minor XSS/log injection risk)
  Decision: Generic message ("Expected SHA256 fingerprint") — FR-5.
```

---

## Delivery Slices

### Slice 1 — Helper + upload path (0.5d)

- Add `import re` (already used in #003; may already be present after that lands)
- Add `_FINGERPRINT_RE = re.compile(r'^SHA256:[A-Za-z0-9.]{43}$')` at module level
  (alongside `_parse_admins` and `_key_type_from_wire`)
- Add `validate_fingerprint(fp: str) -> str` at module level
- Call it in `determine_public_key` after cleaning step
- Unit tests `tests/test_fingerprint_validation.py`:
  - AC-1: valid fingerprint passes
  - AC-2: fingerprint with extra `:` → 400
  - AC-3: fingerprint with `*` or `?` → 400
  - AC-4: empty string → 400
  - AC-5: uncleaned fingerprint with `/` or `+` → 400
  - AC-6: error detail does not contain the raw fingerprint

### Slice 2 — Apply to all four path-param endpoints (0.5d)

- Add `validate_fingerprint(finger_print)` at the top of:
  - `destroy_user_keypair`
  - `inactivate_user_keypair`
  - `refresh_user_keypair`
  - `update_user_notes`
- **Sequencing note (ER round-1):** each of these functions begins with a
  `logger.info(f"... fingerprint: {finger_print}")` call. Place
  `validate_fingerprint(finger_print)` **before** that log line (as the very
  first statement) so that malformed fingerprints do not appear in logs before
  the 400 is raised.
- Integration tests (mock Redis) — use `patch("app.app.state", MagicMock(redis_client=mock_redis))`
  as established in `tests/test_key_parsing.py`:
  - AC-8: malformed fingerprint to each endpoint → 400 (not 404, not 500)
  - AC-7: valid fingerprint to each endpoint → proceeds normally (no regression)

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Regex too strict — rejects valid paramiko output | Low | Medium | Test against `paramiko.Ed25519Key.generate()` and `RSAKey.generate()` output before merging |
| {43} length wrong for some key type | Low | Low | SHA256 of any key is always 32 bytes → 43 base64 chars; verified against OpenSSH spec |
| MD5 legacy fingerprints rejected | Medium | Low | MD5 is deprecated in OpenSSH since 6.8 (2015); document SHA256-only support |
| #003 not yet landed when #004 is implemented | Medium | Low | `import re` may need to be added; `_FINGERPRINT_RE` placement must not conflict with `_key_type_from_wire` |

---

## Definition of Done

- [ ] `_FINGERPRINT_RE = re.compile(r'^SHA256:[A-Za-z0-9.]{43}$')` added at module level
- [ ] `validate_fingerprint(fp: str) -> str` implemented and module-level
- [ ] Called in `determine_public_key` after cleaning step
- [ ] Called at top of `destroy_user_keypair`, `inactivate_user_keypair`, `refresh_user_keypair`, `update_user_notes`, **before** the opening `logger.info()` call in each function
- [ ] Error message does not reflect the raw fingerprint value
- [ ] Unit tests in `tests/test_fingerprint_validation.py` cover AC-1 through AC-6
- [ ] Integration tests confirm malformed fingerprints return 400 at all four path-param endpoints
- [ ] Valid fingerprint uploads and operations unaffected (AC-7 regression tests pass)
- [ ] `import re` confirmed present (may land with #003)
- [ ] Docstrings updated on `destroy_user_keypair`, `inactivate_user_keypair`, `refresh_user_keypair`, `update_user_notes` to document accepted fingerprint format (`SHA256:[A-Za-z0-9.]{43}`) and new HTTP 400 response (FastAPI renders these into the OpenAPI `/docs` UI)
- [ ] `TESTING.md` updated: new row for `tests/test_fingerprint_validation.py` in the Test Files table; new row for `validate_fingerprint()` (target: 100%) in the Coverage Goals table
- [ ] `README.md` Test Coverage table updated to include `tests/test_fingerprint_validation.py`

---

## Board Review

**Verdict:** CLEAR WITH WARNINGS  
**Date:** 2026-04-07  
**Rounds:** 1

| Reviewer | Result | Amended | Key findings |
|---|---|---|---|
| research-handbook | — SKIP | N | Technology well-understood; no unknowns |
| codebase-arch-review | — SKIP | N | Single service, no boundary changes |
| codebase-eng-review | ⚠️ WARN | Y | validate_fingerprint() must precede logger.info; always patch Redis in tests; import re already present |
| codebase-doc-review | ⚠️ WARN | Y | Endpoint docstrings, TESTING.md, README.md coverage table all need updating; DoD gaps added |
| security-review | ⚠️ WARN | Y | Log-before-validate ordering fixed; regex anchoring documented; 404 echo post-validation confirmed safe |
| codebase-ux-review | — SKIP | N | Pure backend change; no user-facing surface |

**Accepted warnings:**
- `import re` already present at line 11 — Slice 1 step to add it is a no-op
- `_` (underscore) in ingress regex `[\w.]` but not in app regex `[A-Za-z0-9.]` — correct and intentional; SHA256 base64 never produces `_`
- Existing 404/403 messages echo fingerprint post-validation — safe; only valid fingerprints reach those lines

**ADRs written:** 0 (ADRs are in the task file itself)  
**Unresolved decisions:** none

### Reviewer output

<details>
<summary>codebase-eng-review — Round 1 (⚠️ PASS WITH WARNINGS)</summary>

## Issues

MINOR | regex correctness | `_` (underscore) is in `[\w.]` (ingress allows it) but is NOT in `[A-Za-z0-9.]` (app regex). SHA256 base64 output never contains `_` — both are correct independently. No action required.

MINOR | FR-5 / echo risk | Existing 404 and 403 HTTPException `detail` strings at lines 613, 631, 637, 664, 675, 735, 742 echo `finger_print` back in responses. FR-5 only requires the 400 validation error not echo it — acceptable since only valid fingerprints reach those lines after #004 lands.

MINOR | logger lines pre-validation | At lines 608, 623, 656, 727 the `logger.info(f"... fingerprint: {finger_print}")` fires before the planned `validate_fingerprint()` call. Implementation must place `validate_fingerprint()` before those log lines.

INFO | `import re` already present | Line 11 of app.py. The plan's risk item "may need to be added" is moot.

INFO | call site count confirmed | All 5 call sites identified in the plan are confirmed correct. No additional unprotected fingerprint usages exist.

INFO | `destroy_user_keypair` has no blacklist check | Unlike the other three path-param endpoints, goes directly to `redis.hgetall`. Validate-before-hgetall placement is confirmed optimal.

INFO | `_` in ingress regex vs app regex | Ingress: `[\w.]` = `[A-Za-z0-9_.]`. App regex: `[A-Za-z0-9.]`. SHA256 base64 output never contains `_`. Tighter app regex is correct.

INFO | AC-8 scope vs ingress constraint | AC-8 only testable via direct TestClient calls that bypass nginx. Fine for unit/integration tests.

INFO | `found.fingerprint` format | Paramiko's `fingerprint` property returns base64 with `+`, `/`, trailing `=`. Cleaning step applied before `validate_fingerprint()`. Resulting 43-char body will contain only `[A-Za-z0-9.]`.

## Amendments
- Added sequencing note to Slice 2: `validate_fingerprint()` must be placed before `logger.info` call at top of each endpoint.
- Added `patch("app.app.state", MagicMock(redis_client=mock_redis))` mock pattern requirement to Slice 2 integration tests.

## Status
PASS WITH WARNINGS

</details>

<details>
<summary>codebase-doc-review — Round 1 (⚠️ PASS WITH WARNINGS)</summary>

## Issues

HIGH | README.md — Test Coverage table lists only `test_admin_logic.py` and `test_blacklist.py`; new `tests/test_fingerprint_validation.py` must be added

HIGH | TESTING.md — "Test Files" table and "Test Structure" section document only two test files; `test_fingerprint_validation.py` needs its own entry

HIGH | TESTING.md — "Coverage Goals" table missing row for `validate_fingerprint()` (target: 100%)

HIGH | app.py docstrings — Four endpoint docstrings must document accepted fingerprint format and new HTTP 400 response; FastAPI renders these into the `/docs` OpenAPI UI

HIGH | app.py docstring — `determine_public_key` inner function docstring does not mention fingerprint validation before return

MEDIUM | README.md — "Admin endpoints" paragraph mentions `DELETE /destroy/{username}/{finger_print}` but never documents format constraint

MEDIUM | plan DoD — missing checkboxes for docstring updates, TESTING.md, README.md (now added)

LOW | TESTING.md — "Writing New Tests" guidance is blacklist-specific; pointer to new file would help

LOW | app.py — existing 404 messages echo `finger_print`; FR-5 was silent on whether in scope (now clarified as exempt post-validation)

Confirmed NOT needing updates: CHANGELOG (none exists), blacklist.txt.example, TODO.md, ADRs.

## Amendments
- Added three DoD checkboxes: TESTING.md update, README.md table update, endpoint docstring updates.
- Added clarifying sentence to FR-5 exempting post-validation 404 messages.

## Status
PASS WITH WARNINGS

</details>

<details>
<summary>security-review — Round 1 (⚠️ PASS WITH WARNINGS)</summary>

## Issues

| Severity | Area | Description |
|---|---|---|
| MEDIUM | Log injection | All four path-param endpoints call `logger.info(f"... fingerprint: {finger_print}")` before `validate_fingerprint()` fires. Hostile internal caller can inject newline sequences or ANSI codes. Plan now requires validation before the opening logger.info. |
| LOW | Anchoring clarification | Plan did not explicitly close the open question on `re.match` + `^...$` anchoring. Added comment to Architecture code block explaining equivalence to `re.fullmatch`. |
| LOW | Residual fingerprint reflection | Lines 613, 629, 637, 662, 675, 742 echo `finger_print` in 404/403 detail strings. Post-validation these are allowlist-safe. |
| INFO | FR-4 call-site ordering | Plan diagrams showed placement before blacklist/Redis but not before logger.info. Now explicit. |
| INFO | `re` already imported | Line 11. Delivery Slice 1 "Add import re" step is a no-op. |

## Amendments
- FR-4 strengthened: validate_fingerprint() must be called before opening logger.info() in each endpoint.
- Architecture code block: added multi-line comment on re.match + $ anchoring equivalence.
- Call-site examples: updated to show validate_fingerprint() before logger.info() in all four endpoints.
- DoD: updated to explicitly require placement before logger.info().

## Status
PASS WITH WARNINGS

</details>
