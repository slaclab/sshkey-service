# 003 — Comment-Field Key Type Injection

**Status:** 🔎 In Review
**Severity:** HIGH
**Category:** Parsing

---

## Problem & Goal

**Problem:** In `upload_user_public_key → determine_public_key` (app.py ~line 418), the key type used to decode uploaded SSH public keys is extracted from the attacker-controlled `Comment:` field of RFC 4716 (SSH2) key blocks:

```python
if line.strip().startswith("Comment:"):
    comment = line.strip().split(':', 1)[1].strip()
    if "ED25519" in comment:
        key_type = "ssh-ed25519"
    elif "RSA" in comment:
        key_type = "ssh-rsa"
```

This `key_type` string is then passed directly to `paramiko.PKey.from_type_string(key_type, ...)` to select the decoder. The comment is free-form text that anyone can set to anything — it is **not** a reliable signal for key type.

Two concrete failure modes:
1. **Injection:** Upload a valid RSA key with `Comment: "256-bit ED25519 ..."` → parser picks `ssh-ed25519`, passes RSA bytes to the ED25519 decoder → raises an exception currently caught and returned as 400. Noisy, potentially exploitable if paramiko behaviour changes.
2. **Rejection of valid keys:** Upload any key whose comment doesn't contain `"ED25519"` or `"RSA"` (e.g. `Comment: "my laptop key"`, or an ECDSA key) → `key_type` stays `None` → upload rejected with 400, even though the key is perfectly valid.

The authoritative key type is already encoded in the first 4+N bytes of the base64 key data itself (OpenSSH wire format). The comment field carries zero authority.

**Goal:** Derive `key_type` exclusively from the decoded wire-format bytes, making the comment field irrelevant to parsing.

**Success metric:**
- An RSA key with `"ED25519"` in the comment uploads and is correctly stored as `ssh-rsa`
- An ED25519 key with `"RSA"` in the comment uploads and is correctly stored as `ssh-ed25519`
- A key with a comment like `"my laptop key"` (no type keyword) uploads successfully
- A genuinely malformed key (truncated base64, wrong bytes) is rejected with a clear 400

**Out of scope:**
- Adding support for new key types (ECDSA, ECDSA-SK, Ed25519-SK) — that is a separate feature
- Changing the OpenSSH one-liner format path (`ssh-ed25519 AAAA... comment`) — not used by this function
- Validating key strength minimums (key size policy) — separate concern

**Constraints:**
- `paramiko` already a dependency — no new libraries
- `struct` is stdlib — no new dependencies at all
- Must be backward-compatible for all existing upload clients

---

## Requirements

### Functional Requirements

```
FR-1: key_type is derived from the OpenSSH wire-format type prefix in the base64 key data
FR-2: The Comment: field is parsed and ignored for key type determination
FR-3: Any key type string that paramiko.PKey.from_type_string() accepts is valid
FR-4: Malformed base64 (decode error) returns HTTP 400 with a clear message
FR-5: Truncated wire data (< 4 bytes, or type_len overflows data) returns HTTP 400
FR-6: An unrecognised wire type string (paramiko rejects it) returns HTTP 400
FR-7: The comment field MAY be preserved as informational metadata (non-blocking)
FR-8: _key_type_from_wire() is a standalone, importable, unit-testable helper
```

### Non-functional Requirements

```
NFR-1: No new dependencies — struct is stdlib, paramiko is already present
NFR-2: No change to the external API contract (POST /upload/{username} unchanged)
NFR-3: No change to stored Redis data shape — key_type stored via pkey.get_name() as before
NFR-4: Performance neutral — struct.unpack on a few bytes adds < 1µs
```

### Acceptance Criteria

```
AC-1: RSA key + "ED25519" comment → uploads successfully, stored key_type is "ssh-rsa"
AC-2: ED25519 key + "RSA" comment → uploads successfully, stored key_type is "ssh-ed25519"
AC-3: ED25519 key + "my laptop key" comment (no type keyword) → uploads successfully
AC-4: Truncated base64 (< 4 decoded bytes) → HTTP 400
AC-5: Wire type_len field overflows available data → HTTP 400
AC-6: Unknown wire type (e.g. "x-fake-key") → HTTP 400 (paramiko rejects it)
AC-7: Valid RSA key with no comment at all → uploads successfully (key_type still resolved)
AC-8: Existing valid uploads with correct comments are unaffected
```

---

## Architecture

### Exact Code Change — app.py

**Current `determine_public_key` logic (lines ~407–432):**

```python
in_key_block = False
key_data_base64 = ""
key_type = None
for line in public_key.public_key.splitlines():
    ...
    if in_key_block:
        if line.strip().startswith("Comment:"):
            comment = line.strip().split(':', 1)[1].strip()
            if "ED25519" in comment:
                key_type = "ssh-ed25519"
            elif "RSA" in comment:
                key_type = "ssh-rsa"
            continue
        else:
            key_data_base64 += line.strip()

if not key_data_base64 or not key_type:          # ← key_type check here is the bug
    raise HTTPException(status_code=400, ...)

found = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_data_base64))
```

**New helper (add near top of app.py, after imports, alongside `_parse_admins`):**

```python
def _key_type_from_wire(data: bytes) -> str:
    """Extract the key type string from OpenSSH wire-format public key data.

    The OpenSSH wire format begins with a 4-byte big-endian length followed by
    the key type string (e.g. b'ssh-ed25519', b'ssh-rsa'). This is the
    authoritative source of key type — not the RFC 4716 Comment: field.

    Raises ValueError on malformed data (too short, length overflow, unreasonable length).
    """
    if len(data) < 4:
        raise ValueError(f"Key data too short: {len(data)} bytes")
    (type_len,) = struct.unpack('>I', data[:4])
    if type_len > 256:
        raise ValueError(f"Key type length {type_len} exceeds sanity limit of 256 bytes")
    if type_len > len(data) - 4:
        raise ValueError(
            f"Key type length {type_len} overflows data length {len(data) - 4}"
        )
    return data[4:4 + type_len].decode('ascii')
```

**Updated `determine_public_key` inner function:**

```python
import re
_RFC4716_HEADER_RE = re.compile(r'^[A-Za-z][A-Za-z0-9-]*:')

in_key_block = False
in_header = False
key_data_base64 = ""
for line in public_key.public_key.splitlines():
    if line.strip() == "---- BEGIN SSH2 PUBLIC KEY ----":
        in_key_block = True
        continue
    elif line.strip() == "---- END SSH2 PUBLIC KEY ----":
        break
    if in_key_block:
        # RFC 4716 §3.3: headers are "Tag: value" lines; continuation
        # lines end with '\'. Skip all header lines (Comment, Subject, x-*).
        if in_header:
            # Still in a multi-line header continuation
            in_header = line.rstrip().endswith('\\')
            continue
        if _RFC4716_HEADER_RE.match(line.strip()):
            in_header = line.rstrip().endswith('\\')
            continue
        key_data_base64 += line.strip()

if not key_data_base64:
    raise HTTPException(status_code=400,
        detail="Invalid public key format. Please ensure it is in the correct format.")

try:
    raw = base64.b64decode(key_data_base64)
    wire_type = _key_type_from_wire(raw)
    found = paramiko.PKey.from_type_string(wire_type, raw)
except ValueError as e:
    logger.debug(f"Key parse ValueError: {e}")
    raise HTTPException(status_code=400,
        detail="Could not parse the public key. Please ensure it is in the correct format.")
except Exception as e:
    logger.debug(f"Key parse error: {e}")
    raise HTTPException(status_code=400,
        detail="Could not parse the public key. Please ensure it is in the correct format.")
```

### Data flow (unchanged externally)

```
POST /upload/{username}
  │  body: RFC 4716 SSH2 public key block
  ▼
determine_public_key()
  │  1. collect base64 lines (Comment: skipped)
  │  2. base64.b64decode → raw bytes
  │  3. _key_type_from_wire(raw) → "ssh-ed25519" / "ssh-rsa" / ...
  │  4. paramiko.PKey.from_type_string(wire_type, raw) → PKey object
  │  5. pkey.get_name() → stored key_type in Redis (unchanged)
  ▼
Redis hset (no schema change)
```

No API contract changes. No Redis schema changes. No Kubernetes changes.

### `struct` import

`struct` is already used elsewhere in Python stdlib-heavy codebases; add to imports at top of app.py:

```python
import struct
```

---

## ADRs

### ADR-001: Wire-format extraction vs. paramiko auto-detection

**Status:** Accepted
**Date:** 2026-04-07

**Context:** We need to derive key type from the key bytes, not the comment. Two approaches:
- **Option A:** Extract the type string from the raw bytes ourselves using `struct.unpack`, then pass it to `paramiko.PKey.from_type_string`.
- **Option B:** Let paramiko auto-detect by trying each registered key type until one succeeds (no such public API exists in paramiko 4.x).
- **Option C:** Use `paramiko.Message` to parse the wire format (internal API, undocumented).

**Decision:** Option A — explicit `struct.unpack` extraction.
**Rationale:** Explicit, readable, and directly testable without paramiko involvement. Option B has no clean public API in paramiko 4.x. Option C uses undocumented internals that could change. The wire format (RFC 4253 §6.6) is a stable standard that won't change.
**Consequence:** If a future key type uses a different wire format prefix convention (unlikely — all current types follow RFC 4253), the helper would need updating.

### ADR-002: Comment field — drop vs. preserve as metadata

**Status:** Accepted
**Date:** 2026-04-07

**Context:** The current code parses the `Comment:` field for key type. After the fix, the comment has no security role. Should we still parse and store it?

**Options:**
- **A:** Drop comment parsing entirely — simplest, no metadata stored.
- **B:** Parse comment and store as informational field in Redis bundle.

**Decision:** Option A — drop comment parsing. The comment is not currently stored in Redis anyway (the bundle uses `pkey.get_name()` for key type and there is no `comment` field). Storing it is a separate feature request.
**Consequence:** Comment text is silently discarded. This is correct behaviour — the comment was never authoritative.

---

## Migration & Transition Path

No migration required — additive change.

- No API contract changes (same endpoint, same request/response shape)
- No Redis schema changes (key_type still stored via `pkey.get_name()`)
- Existing stored keys are completely unaffected (fix is in the upload path only)
- Old and new versions safe to run simultaneously during rollout

---

## Trade-off Analysis

```
Choice: struct.unpack vs. reading paramiko internals
  + struct: explicit, zero new deps, directly unit-testable, stable standard
  + struct: _key_type_from_wire() can be tested without any paramiko objects
  - struct: 3 lines of manual byte parsing (very low complexity)
  Decision: struct. The alternative (paramiko.Message) uses undocumented internals.

Choice: Drop comment entirely vs. store as metadata
  + Drop: simpler, no new Redis fields, no schema migration risk
  - Drop: loses potentially useful user-facing label (low value — key type is already stored)
  Decision: Drop. Comment was never stored before; adding storage is a separate feature.

Choice: Collapse ValueError + Exception into single except vs. separate handling
  + Single: same user-facing message either way (400 "Could not parse...")
  - Single: slightly less debuggable in server logs
  Decision: Separate catches, same user message. Log the ValueError detail at DEBUG level
  so operators can distinguish malformed-wire from paramiko-rejection without leaking
  internals to the user.
```

---

## Delivery Slices

### Slice 1 — Helper + app.py change (0.5d)

**Files:** `app.py` only

- Add `import struct` and `import re` to imports
- Add `_RFC4716_HEADER_RE = re.compile(r'^[A-Za-z][A-Za-z0-9-]*:')` module-level constant
- Add `_key_type_from_wire(data: bytes) -> str` module-level helper (alongside `_parse_admins`)
  - Include `type_len > 256` sanity cap (ER-003 amendment)
- Update `determine_public_key`:
  - Remove `key_type = None` variable
  - Remove `Comment:` → `key_type` dispatch block
  - Replace with general RFC 4716 header skipping using `_RFC4716_HEADER_RE` and `in_header` continuation tracking (ER-003 amendment)
  - Change `if not key_data_base64 or not key_type:` → `if not key_data_base64:`
  - Add `raw = base64.b64decode(key_data_base64)`
  - Add `wire_type = _key_type_from_wire(raw)`
  - Change `paramiko.PKey.from_type_string(key_type, ...)` → `paramiko.PKey.from_type_string(wire_type, raw)`
  - Split exception handling to catch `ValueError` separately
  - Add `logger.debug()` before re-raising HTTPException in both catch blocks (ER-003 amendment)

**Verification:** `grep -n "key_type" app.py` should show zero occurrences inside `determine_public_key`

### Slice 2 — Tests (0.5d)

**File:** `tests/test_key_parsing.py` (new)

Following `tests/test_admin_logic.py` patterns:

```
TestKeyTypeFromWire (unit — no paramiko needed):
  - test_ed25519_wire_type_extracted_correctly
  - test_rsa_wire_type_extracted_correctly
  - test_too_short_raises_value_error
  - test_type_len_overflow_raises_value_error
  - test_type_len_exceeds_sanity_limit_raises_value_error      ← ER-003 amendment
  - test_unknown_but_valid_format_returns_string

TestRfc4716HeaderParsing (unit — parsing loop only):           ← ER-003 amendment
  - test_multiline_comment_continuation_skipped
  - test_subject_header_skipped
  - test_custom_x_header_skipped
  - test_multiline_header_with_backslash_continuation

TestDeterminePublicKey (integration — uses real paramiko):
  - test_rsa_key_with_ed25519_comment_parsed_as_rsa  (AC-1)
  - test_ed25519_key_with_rsa_comment_parsed_as_ed25519  (AC-2)
  - test_key_with_generic_comment_uploads_successfully  (AC-3)
  - test_key_with_no_comment_uploads_successfully  (AC-7)
  - test_truncated_base64_returns_400  (AC-4)
  - test_malformed_wire_returns_400  (AC-5, AC-6)
  - test_invalid_base64_characters_returns_400                  ← ER-003 amendment

Note: generate test keys at test time via paramiko.Ed25519Key.generate() /
paramiko.RSAKey.generate(2048), extract .get_base64(), and wrap in RFC 4716
format with injected Comment headers. Do not commit private key material.
```

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Wire-format extraction fails on non-standard key encoding | Low | Medium | `ValueError` caught → clean 400; log detail at DEBUG |
| paramiko `from_type_string` rejects a valid wire type string | Low | Low | Same exception path → 400; test against real paramiko-generated keys |
| Users with existing upload scripts break | None | None | RFC 4716 format is unchanged; comment field is still accepted (just ignored) |
| `struct` not imported | Low | Low | stdlib; add to imports in Slice 1 |
| Future paramiko version changes `from_type_string` signature | Low | Medium | Pin paramiko version in requirements.txt; test on upgrade |

---

## Definition of Done

- [ ] `import struct` and `import re` added to app.py
- [ ] `_RFC4716_HEADER_RE` compiled regex added module-level (ER-003 amendment)
- [ ] `_key_type_from_wire(data: bytes) -> str` implemented and module-level
- [ ] `_key_type_from_wire` includes `type_len > 256` sanity cap (ER-003 amendment)
- [ ] `determine_public_key` no longer references `key_type` variable
- [ ] All RFC 4716 headers (Comment, Subject, x-*) skipped via regex, not just Comment (ER-003 amendment)
- [ ] Multi-line header continuations (backslash) handled correctly (ER-003 amendment)
- [ ] `logger.debug()` called before re-raising HTTPException in catch blocks (ER-003 amendment)
- [ ] `grep -n "key_type" app.py` shows zero occurrences inside `determine_public_key`
- [ ] `tests/test_key_parsing.py` created — all injection AC tests passing
- [ ] `tests/test_key_parsing.py` — all wire-format unit tests passing
- [ ] `tests/test_key_parsing.py` — RFC 4716 header parsing tests passing (ER-003 amendment)
- [ ] `tests/test_key_parsing.py` — invalid base64 characters test passing (ER-003 amendment)
- [ ] Existing valid key uploads unaffected (regression tests pass)
- [ ] Error messages for malformed keys remain clear (no internal detail leaked)
- [ ] TESTING.md updated: test file table, run-specific test-file and per-class examples, Test Classes section (TestKeyTypeFromWire, TestRfc4716HeaderParsing, TestDeterminePublicKey), Test Fixtures section (new SSH2 key block fixtures), and coverage goals include `tests/test_key_parsing.py`
- [ ] README.md updated: test coverage table includes `tests/test_key_parsing.py`
