# 002 — Weak Admin Logic

**Status:** 🔍 Reviewed  
**Severity:** HIGH  
**Category:** Auth

---

## Problem & Goal

**Problem:** Admin status is resolved on every incoming request by calling `os.getenv('SLACSSH_ADMINS', '').split(',')` inside the `auth_okay` decorator (app.py line 268). This has four compounding weaknesses:

1. `''.split(',')` returns `['']` — a list containing the empty string. While `auth()` blocks empty usernames today, the intent is ambiguous and one line of code away from a silent bypass.
2. No whitespace normalisation — `"admin1, admin2"` produces `['admin1', ' admin2']`; the second entry silently never matches, locking the operator out of admin endpoints without any error.
3. The env var is re-read on every request — it behaves as if it were mutable at runtime, but there is no audit trail, no logging, and no defined semantics for in-flight changes.
4. Misconfiguration is invisible until an admin action is first attempted in production.

**Goal:** Parse, validate, and normalise `SLACSSH_ADMINS` exactly once at startup into an immutable module-level constant. Any misconfiguration (empty list, whitespace-only entries) surfaces immediately in startup logs, not silently at runtime.

**Success metric:**
- `SLACSSH_ADMINS=" admin1 , , admin2 "` → `{'admin1', 'admin2'}` at module load; warning logged for the empty entry.
- `SLACSSH_ADMINS=""` → `frozenset()` at module load; warning logged that no admins are configured.
- All existing admin-check behaviour is preserved for well-formed inputs.

**Out of scope:**
- Moving the admin list to a database or external identity system
- Role-based access control beyond the current binary admin/non-admin model
- Adding audit logging for admin actions (separate concern)

**Constraints:**
- Backward-compatible: existing deployments using `SLACSSH_ADMINS=user1,user2` must work without changes
- No new dependencies — stdlib only
- Must integrate with the existing `unittest.mock.patch` test patterns in `tests/test_blacklist.py`

---

## Requirements

### Functional Requirements

```
FR-1: SLACSSH_ADMINS is parsed once at module import time into a frozenset
FR-2: Leading/trailing whitespace around each entry is stripped
FR-3: Empty entries (from trailing commas, double commas, whitespace-only) are silently filtered out
FR-4: A startup WARNING is logged if any empty/whitespace entries were present
FR-5: A startup WARNING is logged if the resulting admin set is empty (no admins configured)
FR-6: auth_okay() uses the module-level ADMINS frozenset for all admin checks
FR-7: The _parse_admins() function is importable and directly unit-testable
```

### Non-functional Requirements

```
NFR-1: Zero performance regression — frozenset membership check is O(1), faster than the current list scan
NFR-2: No new module-level side effects beyond what already exists (env var reads at import are already the pattern)
NFR-3: Thread-safe — frozenset is immutable; no locking required for reads
```

### Acceptance Criteria

```
AC-1: Given SLACSSH_ADMINS="admin1,admin2", when the module loads, ADMINS == frozenset({'admin1', 'admin2'}) and no warning is logged
AC-2: Given SLACSSH_ADMINS=" admin1 , , admin2 ", ADMINS == frozenset({'admin1', 'admin2'}) and one warning about empty entries is logged
AC-3: Given SLACSSH_ADMINS="" (or unset), ADMINS == frozenset() and warnings about both empty entries (1 empty from "".split(",")) and no admins are logged
AC-4: Given SLACSSH_ADMINS=",", ADMINS == frozenset() and warnings for both empty entries and no-admins are logged
AC-5: A request to an admin-only endpoint from a known admin succeeds (403 is NOT returned)
AC-6: A request to an admin-only endpoint from a non-admin returns 403
AC-7: A request to a non-admin endpoint where found_username == username succeeds regardless of ADMINS content
```

---

## Architecture

### Exact Code Change — app.py

**Current (line 268, inside `auth_okay` decorator):**
```python
admins = os.getenv('SLACSSH_ADMINS', '').split(',')
found_username = auth(request, user_header)

if not admin_only:
    if found_username != username and found_username not in admins:
        ...
else:
    if found_username not in admins:
        ...
```

**After — new module-level constant (insert after existing env var block, ~line 45):**
```python
def _parse_admins(raw: str) -> frozenset:
    """Parse and normalise the SLACSSH_ADMINS env var into an immutable set.

    Strips whitespace from each entry, filters empty entries, and emits
    startup warnings for misconfiguration. Called once at module load.
    """
    entries = [e.strip() for e in raw.split(',')]
    valid = frozenset(e for e in entries if e)
    empty_count = len(entries) - len(valid)
    if empty_count:
        logger.warning(
            f"SLACSSH_ADMINS contains {empty_count} empty/whitespace "
            f"entries (ignored). Check for trailing commas or spaces."
        )
    if not valid:
        logger.warning(
            "SLACSSH_ADMINS is empty — no admin users configured. "
            "Admin-only endpoints will return 403 for all users."
        )
    return valid

ADMINS: frozenset = _parse_admins(os.getenv('SLACSSH_ADMINS', ''))
```

**After — updated `auth_okay` decorator (line 268, remove `os.getenv` call):**
```python
# Remove: admins = os.getenv('SLACSSH_ADMINS', '').split(',')
found_username = auth(request, user_header)

if not admin_only:
    if found_username != username and found_username not in ADMINS:
        ...
else:
    if found_username not in ADMINS:
        ...
```

### Data Flow (unchanged externally)

```
Request arrives
      │
      ▼
auth_okay decorator
      │  auth() — reads REMOTE-USER header (unchanged)
      │  found_username in ADMINS  ← frozenset lookup (was: list from os.getenv)
      ▼
Route handler
```

No API contract changes. No Redis schema changes. No Kubernetes manifest changes.

---

## ADRs

### ADR-001: Parse at startup vs. per-request

**Status:** Accepted  
**Date:** 2026-04-07

**Context:** The admin list is set via env var at pod launch. It is static for the lifetime of the pod. The current code re-reads and re-parses it on every authenticated request.

**Options considered:**

| Option | Pros | Cons |
|--------|------|------|
| Parse at module load (proposed) | Validates at startup; O(1) lookup; immutable | Config change requires pod restart |
| Parse per-request (current) | Config could theoretically be live-reloaded | Env vars don't change in k8s without restart; creates false mutability impression; no audit trail |
| Parse in `lifespan()` only | Centralises startup logic | `auth_okay` is called before lifespan in some test paths; complicates test setup |

**Decision:** Parse at module load via a module-level constant.  
**Rationale:** Env vars in Kubernetes are fixed at pod start. Parsing at module load is the same pattern already used for `REDIS_HOST`, `REDIS_PORT`, `USERNAME_HEADER_FIELD`, etc. in this codebase. Surfacing misconfiguration at startup is strictly better than at first admin request.  
**Consequence:** A change to `SLACSSH_ADMINS` requires a pod restart — which is already required for all other config changes in this service.

### ADR-002: `frozenset` vs. `list` vs. `set`

**Status:** Accepted  
**Date:** 2026-04-07

**Decision:** `frozenset`.  
**Rationale:** Immutable (cannot be accidentally mutated at runtime), O(1) membership test (vs. O(n) for list), hashable (can be used as dict key or in sets if needed later). The current `list` is O(n) and mutable — both are unnecessary risks for a static config value.

---

## Migration & Transition Path

No migration required — this is an internal refactor with no API, schema, or protocol changes.

- The env var name (`SLACSSH_ADMINS`) and format (`comma-separated usernames`) are unchanged.
- Existing deployments with well-formed `SLACSSH_ADMINS=user1,user2` behave identically.
- The only observable difference is startup log output (new WARNING messages for misconfigured deployments).
- Old and new versions can run simultaneously during rollout with no skew risk.

---

## Trade-off Analysis

```
Choice: Warn on empty admin list vs. refuse to start
  + Warning: backward-compatible; existing deployments without admins configured
    (if any) continue to function
  + Warning: admin endpoints simply return 403 — this is a safe degraded state
  - Warning: operator may not notice the warning in noisy logs
  Decision: Warn. The service is functional without admins; a hard startup failure
  would be a breaking change for any deployment not using admin endpoints.

Choice: frozenset at module level vs. inside lifespan()
  + Module level: matches existing pattern for all other env-var constants
  + Module level: available in unit tests without spinning up the FastAPI app
  - Module level: _parse_admins() runs at import time, including during test imports
  Decision: Module level. The function has no side effects beyond logging; test
  patches on 'app.ADMINS' work cleanly with unittest.mock.patch.
```

---

## Delivery Slices

### Slice 1 — Core implementation (0.5d, app.py only)

**Changes:**
- Add `_parse_admins(raw: str) -> frozenset` function after the existing env var block (~line 45)
- Add `ADMINS: frozenset = _parse_admins(os.getenv('SLACSSH_ADMINS', ''))` module-level constant
- In `auth_okay` (line 268): remove `admins = os.getenv('SLACSSH_ADMINS', '').split(',')`, replace `admins` references with `ADMINS`

**Verification:** `grep -n "os.getenv.*SLACSSH_ADMINS" app.py` returns zero results after the change.

### Slice 2 — Unit tests (0.5d, tests/test_admin_logic.py + tests/conftest.py)

**IMPORTANT:** Loguru does not propagate to Python's standard `logging` module by default.
`pytest.caplog` will NOT capture loguru output unless a propagation fixture is configured.

**New file: `tests/conftest.py`** (loguru → standard logging propagation):
```python
# tests/conftest.py
import logging
import pytest
from loguru import logger

@pytest.fixture(autouse=True)
def propagate_loguru(caplog):
    """Forward loguru output to Python logging so caplog captures it."""
    handler_id = logger.add(
        logging.getLogger("loguru_propagation").handlers[0]
        if logging.getLogger("loguru_propagation").handlers
        else logging.StreamHandler(),
        format="{message}",
    )
    # Alternative simpler approach — use propagate sink:
    class PropagationSink:
        def write(self, message):
            record = message.record
            logging.getLogger("loguru").handle(
                logging.LogRecord(
                    name="loguru",
                    level=record["level"].no,
                    pathname=record["file"].path,
                    lineno=record["line"],
                    msg=record["message"],
                    args=(),
                    exc_info=None,
                )
            )
    # Cleanest approach: add a sink that writes to caplog's handler
    logger.remove(handler_id)
    sink_id = logger.add(
        lambda msg: caplog.handler.emit(
            logging.LogRecord(
                name="loguru",
                level=logging.WARNING,
                pathname="",
                lineno=0,
                msg=str(msg).strip(),
                args=(),
                exc_info=None,
            )
        ),
        level="WARNING",
    )
    with caplog.at_level(logging.WARNING):
        yield
    logger.remove(sink_id)
```

> **Implementer note:** The above is illustrative. The simplest working pattern is:
> ```python
> @pytest.fixture(autouse=True)
> def propagate_loguru(caplog):
>     handler_id = logger.add(caplog.handler, format="{message}", level="WARNING")
>     yield
>     logger.remove(handler_id)
> ```
> Test this first; if `caplog.text` is still empty, use the `LogRecord` approach.

**New file: `tests/test_admin_logic.py`** — following `tests/test_blacklist.py` patterns:

```python
# tests/test_admin_logic.py
import pytest
from unittest.mock import patch
from app import _parse_admins

class TestParseAdmins:
    def test_valid_two_admins(self):
        result = _parse_admins("admin1,admin2")
        assert result == frozenset({'admin1', 'admin2'})

    def test_whitespace_normalisation(self):
        result = _parse_admins(" admin1 , admin2 ")
        assert result == frozenset({'admin1', 'admin2'})

    def test_empty_string(self, caplog):
        result = _parse_admins("")
        assert result == frozenset()
        # "".split(",") → [""] — 1 empty entry, plus no admins warning
        assert "empty" in caplog.text.lower()
        assert "no admin users configured" in caplog.text.lower()

    def test_only_commas(self, caplog):
        result = _parse_admins(",,,")
        assert result == frozenset()
        # AC-4: both empty-entries and no-admins warnings must fire
        assert "empty" in caplog.text.lower()
        assert "no admin users configured" in caplog.text.lower()

    def test_empty_entry_in_middle(self, caplog):
        result = _parse_admins("admin1,,admin2")
        assert result == frozenset({'admin1', 'admin2'})
        assert "empty" in caplog.text.lower()

    def test_single_admin(self):
        result = _parse_admins("admin1")
        assert result == frozenset({'admin1'})

    def test_whitespace_only_entry(self, caplog):
        result = _parse_admins("admin1,   ,admin2")
        assert result == frozenset({'admin1', 'admin2'})
        assert "empty" in caplog.text.lower()

    def test_returns_frozenset(self):
        result = _parse_admins("admin1")
        assert isinstance(result, frozenset)


class TestAdminCheckInAuthOkay:
    """Integration tests for the admin check using patch('app.ADMINS').
    
    These use the same mock pattern as test_blacklist.py — mock the auth()
    function to return a controlled username, and patch ADMINS to a known set.
    """

    @pytest.mark.asyncio
    async def test_admin_user_passes_admin_only_endpoint(self):
        """AC-5: Admin user can access admin-only endpoint."""
        from app import destroy_user_keypair
        from unittest.mock import Mock, AsyncMock
        from fastapi import HTTPException
        import redis.asyncio as aioredis

        mock_request = Mock()
        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=1)

        with patch('app.ADMINS', frozenset({'superuser'})):
            with patch('app.auth', return_value='superuser'):
                # destroy_user_keypair is @auth_okay(admin_only=True)
                # Should NOT raise 403
                try:
                    await destroy_user_keypair(
                        request=mock_request,
                        username='targetuser',
                        finger_print='SHA256:abc123',
                        redis=mock_redis,
                        found_username=None,
                    )
                except HTTPException as e:
                    assert e.status_code != 403, f"Admin should not get 403, got {e.status_code}"

    @pytest.mark.asyncio
    async def test_non_admin_blocked_from_admin_only_endpoint(self):
        """AC-6: Non-admin is blocked from admin-only endpoint."""
        from app import destroy_user_keypair
        from unittest.mock import Mock, AsyncMock
        from fastapi import HTTPException

        mock_request = Mock()
        mock_redis = AsyncMock()

        with patch('app.ADMINS', frozenset({'superuser'})):
            with patch('app.auth', return_value='regularuser'):
                with pytest.raises(HTTPException) as exc_info:
                    await destroy_user_keypair(
                        request=mock_request,
                        username='targetuser',
                        finger_print='SHA256:abc123',
                        redis=mock_redis,
                        found_username=None,
                    )
                assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_access_other_users_non_admin_endpoint(self):
        """AC-7 (admin path): Admin accessing another user's non-admin endpoint."""
        from app import list_user_keypair
        from unittest.mock import Mock, AsyncMock
        from fastapi import HTTPException

        mock_request = Mock()
        mock_redis = AsyncMock()
        mock_redis.scan_iter = AsyncMock(return_value=AsyncMock(__aiter__=lambda self: self, __anext__=AsyncMock(side_effect=StopAsyncIteration)))

        with patch('app.ADMINS', frozenset({'superuser'})):
            with patch('app.auth', return_value='superuser'):
                try:
                    await list_user_keypair(
                        request=mock_request,
                        username='anotheruser',
                        redis=mock_redis,
                        found_username=None,
                    )
                except HTTPException as e:
                    assert e.status_code != 403, f"Admin should not get 403, got {e.status_code}"
```

### Slice 3 — .env.example update (0.1d)

Add comment to `.env.example`:
```bash
# Comma-separated list of admin usernames. Whitespace around commas is ignored.
# Example: SLACSSH_ADMINS=alice,bob,charlie
# Leave empty to disable admin endpoints (all admin actions return 403).
SLACSSH_ADMINS=
```

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Existing deployment with `SLACSSH_ADMINS=user1, user2` (space after comma) suddenly works correctly where it was silently broken before | Medium | Low (positive fix) | Communicate in release notes as a bug fix |
| Test imports of `app` trigger `_parse_admins` before `SLACSSH_ADMINS` is patched | Low | Low | `_parse_admins` is pure and side-effect free; tests patch `app.ADMINS` directly, not the env var |
| Logger not yet initialised when `_parse_admins` is called at module load | Low | Low | loguru's `logger` is a module-level singleton imported on line 11 of app.py; it is available before the env var block |
| `frozenset` type annotation requires Python 3.9+ for `frozenset[str]` | Low | Low | Use `frozenset` without subscript (or `from __future__ import annotations`) to stay compatible |
| Admin matching is case-sensitive; if identity provider sends mixed-case usernames (e.g. `Admin1` vs `admin1` in env var), admin check silently fails | Low | Medium (admin lockout) | Document case-sensitivity in `.env.example` and `_parse_admins` docstring. Consider `.lower()` normalisation in a future PR if mixed-case IdPs are encountered. *(Added by security review round 1)* |

---

## Definition of Done

- [ ] `_parse_admins()` function added to app.py with strip + filter + warning logic
- [ ] `ADMINS: frozenset` module-level constant replaces per-request `os.getenv` call
- [ ] `auth_okay` decorator references `ADMINS` only — `os.getenv('SLACSSH_ADMINS')` no longer appears in app.py
- [ ] `tests/conftest.py` created with loguru → caplog propagation fixture *(added by eng review round 1)*
- [ ] `tests/test_admin_logic.py` created with all 8 unit tests for `_parse_admins` passing
- [ ] Integration tests for admin check in `auth_okay` (patch `app.ADMINS`) passing
- [ ] Startup WARNING verified in logs when `SLACSSH_ADMINS` is empty
- [ ] `.env.example` updated with whitespace-handling note
- [ ] `README.md` updated with `SLACSSH_ADMINS` configuration documentation (env var format, whitespace handling, empty-list behaviour)
- [ ] `TESTING.md` updated to list `tests/test_admin_logic.py` test classes (`TestParseAdmins`, `TestAdminCheckInAuthOkay`)
- [ ] `grep -n "os.getenv.*SLACSSH_ADMINS" app.py` returns zero results

---

## Board Review

**Verdict:** CLEAR WITH WARNINGS
**Date:** 2026-04-07
**Rounds:** 1

| Reviewer | Result | Amended | Key findings |
|---|---|---|---|
| research-handbook | — SKIP | N | Technology well-understood; no unknowns |
| codebase-arch-review | — SKIP | N | Single-service internal refactor; no boundary changes |
| codebase-eng-review | ⚠️ WARN | Y | conftest.py needed for loguru/caplog; integration test stubs filled in; AC-3 dual-warning clarified |
| codebase-doc-review | ⚠️ WARN | Y | README.md and TESTING.md gaps added to DoD |
| security-review | ⚠️ WARN | Y | Strict improvement; case-sensitivity documented in risk register |
| codebase-ux-review | — SKIP | N | Pure backend refactor; no user-facing surface |

**Accepted warnings:**
- loguru/caplog incompatibility resolved in plan via conftest.py fixture
- Case-sensitive admin matching preserved and documented; `.lower()` deferred to future PR
- README.md and TESTING.md update added to DoD (in-scope for Slice 3)

**ADRs written:** 0 (ADRs already in plan; no new docs/adr/ directory needed for this scope)
**Unresolved decisions:** none

### Reviewer output

<details>
<summary>codebase-eng-review — Round 1 (⚠️ WARN)</summary>

# Engineering Review — 002 Weak Admin Logic

**Reviewer:** codebase-eng-review
**Date:** 2026-04-07
**Plan:** todo/002-weak-admin-logic.md
**Round:** 1

## Summary

- Plan is well-scoped, low-risk, and correctly addresses the identified parsing/normalisation bugs in admin list handling.
- The core `_parse_admins()` implementation is correct and the `auth_okay` refactor is mechanical.
- **Blocking issue (resolved):** Test plan uses `pytest.caplog` to capture loguru output, but loguru does NOT propagate to Python's standard `logging` module by default — `caplog` will be empty. A `conftest.py` fixture is required. Added to plan.
- **Minor gap (resolved):** `test_only_commas` and `test_empty_string` had incomplete log assertions; updated per AC-4.
- Integration test stubs replaced with concrete implementations using `patch('app.auth')` + `patch('app.ADMINS')`.

## Issues

| # | Severity | Area | Description |
|---|----------|------|-------------|
| 1 | BLOCKING (resolved) | Test infra | `caplog` does not capture loguru output — added conftest.py propagation fixture to plan |
| 2 | MEDIUM (resolved) | Test coverage | `test_only_commas` missing both warning assertions for AC-4 |
| 3 | MEDIUM (resolved) | Test coverage | `test_empty_string` missing empty-entries warning assertion |
| 4 | LOW (resolved) | Test coverage | Integration test stubs were `...` placeholders — replaced with concrete implementations |
| 5 | LOW (resolved) | Plan clarity | AC-3 only mentioned "no admins" warning; updated to note both warnings fire for `""` |
| 6 | LOW (resolved) | Plan clarity | Risk register had inaccurate `logger.getLogger(...)` reference — corrected to loguru singleton |
| 7 | LOW | Type annotation | `frozenset` without type param; `frozenset[str]` preferred for clarity (Python 3.11) |
| 8 | INFO | Edge case | Case-insensitive matching out of scope — noted in security review |
| 9 | INFO | Observability | Suggest logging parsed ADMINS set at INFO level at startup |

## Decisions Required

All decisions defaulted or resolved. See plan for details.

## Amendments

1. AC-3 updated — dual-warning behaviour clarified
2. Slice 2 expanded — added `tests/conftest.py` with loguru→caplog propagation fixture
3. Slice 2 test code updated — log assertions corrected for `test_only_commas` and `test_empty_string`
4. Integration test stubs replaced with concrete implementations
5. Risk register logger reference corrected
6. Definition of Done updated — added `tests/conftest.py` checklist item

## Status

PASS WITH WARNINGS

</details>

<details>
<summary>codebase-doc-review — Round 1 (⚠️ WARN)</summary>

# Doc Review — 002 Weak Admin Logic

**Reviewer:** codebase-doc-review
**Date:** 2026-04-07
**Plan file:** todo/002-weak-admin-logic.md

## Summary

- `.env.example` correctly identified as needing `SLACSSH_ADMINS` entry — covered in Slice 3 and DoD.
- README.md has zero mention of `SLACSSH_ADMINS`, admin endpoints, or admin configuration. Added to DoD.
- TESTING.md only documents blacklist tests; new `tests/test_admin_logic.py` must be listed. Added to DoD.
- No CHANGELOG, CONTRIBUTING, ARCHITECTURE, or ADR directory exists — not blocking for this scope.
- Risk Register "communicate in release notes" mitigation is currently unactionable (no release-notes mechanism exists).

## Issues

| # | Severity | Area | Description |
|---|----------|------|-------------|
| 1 | HIGH (resolved) | README.md | No mention of `SLACSSH_ADMINS`, admin endpoints, or startup warning behaviour — added to DoD |
| 2 | MEDIUM (resolved) | TESTING.md | New test file not listed — added to DoD |
| 3 | LOW | README.md | "Testing" section implies single test file `test_blacklist.py` |
| 4 | LOW | Risk Register | "Communicate in release notes" mitigation unactionable — no CHANGELOG mechanism |
| 5 | INFO | .env.example | Already covered — confirmed absent today, addition is correct |

## Amendments

1. Added DoD item: `README.md updated with SLACSSH_ADMINS configuration documentation`
2. Added DoD item: `TESTING.md updated to list test_admin_logic.py test classes`

## Status

PASS WITH WARNINGS

</details>

<details>
<summary>security-review — Round 1 (⚠️ WARN)</summary>

# Security Review — 002-weak-admin-logic — Round 1

**Reviewer:** security-review subagent
**Date:** 2026-04-07
**Scope:** Auth/authz, injection, secrets, input validation, supply chain

## Summary

- The proposed change is a strict security improvement: eliminates `['']` phantom-entry risk, adds whitespace normalisation, makes admin set immutable and O(1).
- Warn-not-fail on empty `ADMINS` is the safe direction — results in 403 for all admin endpoints, never 200. No privilege escalation path.
- No injection surface: env var consumed only as `frozenset` membership test — no shell, SQL, or template expansion.
- Pre-existing REMOTE-USER header-trust issue (#001) is the dominant auth risk; this change neither worsens nor addresses it (correctly out of scope).
- Case-sensitive matching preserved but undocumented — added to Risk Register.

## Issues

| # | Severity | Area | Description |
|---|----------|------|-------------|
| 1 | LOW (documented) | Auth | Case-sensitive admin matching undocumented — added to Risk Register and .env.example note |
| 2 | INFO | Auth | `['']` weakness currently mitigated by `auth()` rejecting empty usernames — fix removes fragile dependency |
| 3 | INFO | Auth | `frozenset.__contains__` not susceptible to timing attacks for username enumeration |
| 4 | INFO | Injection | No injection path via `str.split` → `str.strip` → `frozenset` |
| 5 | INFO | Supply chain | No new dependencies — stdlib only |
| 6 | INFO | Interaction | #001 header-spoofing is orthogonal; this change does not alter that attack surface |

## Amendments

- Added case-sensitive matching risk to plan's Risk Register

## Status

PASS WITH WARNINGS

</details>
