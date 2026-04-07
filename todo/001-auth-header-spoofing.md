# 001 — Auth Header Spoofing

**Status:** ⬜ Open  
**Severity:** HIGH (revised from CRITICAL — see Threat Model)  
**Category:** Auth

---

## Problem & Goal

**Problem:** `app.py` trusts the `REMOTE-USER` header (or whatever `SLACSSH_USERNAME_HEADER_FIELD`
is configured to) unconditionally. The `auth()` function at line 268 reads the header value from
the incoming request and accepts it as the authenticated username with no further verification.
There is no allowlist of trusted proxy IPs, no shared secret, and no NetworkPolicy restricting
which pods can reach the service.

```python
# app.py line 268 — trusts whatever is in the header, no other verification
found_username = request.headers.get(user_header)
```

**Revised threat model (see full analysis below):** External exploitation via HTTPS is
**already mitigated** by the nginx `configuration-snippet` which unconditionally overwrites
`Remote-User` with the Vouch-authenticated identity before forwarding. The real exploitable
surface today is **internal** — any other pod in the cluster can reach port 8000 directly and
inject an arbitrary username header, bypassing nginx and Vouch entirely.

**Goal:** Close the internal cluster attack surface with a NetworkPolicy, add defence-in-depth
at the app layer with a shared proxy secret, and document the security model so future Ingress
rules don't accidentally reintroduce the external exposure.

**Success metric:**
1. No pod other than the nginx ingress controller can reach `slac-ssh-mfa:8000` (enforced by NetworkPolicy)
2. A forged header sent directly to port 8000 is rejected with HTTP 401 when `SLACSSH_PROXY_SECRET` is configured
3. The security contract (overwrite vs. strip, NetworkPolicy label requirements) is documented

**Out of scope:**
- Replacing header-based auth with token-based auth (requires proxy + consumer changes)
- Adding mTLS between proxy and service
- Changing the username header field name

**Constraints:**
- Must remain compatible with the existing Vouch + nginx-ingress setup at SLAC
- No new external auth library dependencies
- Kubernetes-only deployment target

---

## Threat Model

This section documents the actual exploitability of the header injection issue given the
current nginx + Vouch deployment, so priority and sequencing decisions are grounded in reality.

### Why external exploitation is already blocked

Every authenticated Ingress resource contains:
```yaml
nginx.ingress.kubernetes.io/configuration-snippet: |
  proxy_set_header Remote-Name $http_x_vouch_idp_claims_name;
  proxy_set_header Remote-User $http_x_vouch_idp_claims_name;
```

This is an **overwrite**, not a strip. nginx replaces `Remote-User` with whatever Vouch
returned for the validated session, regardless of what the client sent. A browser-originating
attacker hitting `slac-ssh-mfa.slac.stanford.edu` over HTTPS **cannot** influence the
`Remote-User` value that reaches the app.

### Where real risk exists

| Attack vector | Exploitable? | Why |
|---|---|---|
| External browser forges `Remote-User` on auth'd routes | ❌ No | nginx overwrites the header unconditionally |
| External browser hits `/` (frontpage Ingress) | ⚠️ No auth, no overwrite | But `auth()` is not called on `/`, so no exploit today |
| External browser hits `/authorized_keys/` (auth Ingress) | ⚠️ No auth, no overwrite | But `/authorized_keys/` doesn't call `auth()` either, so no exploit today |
| Pod inside cluster hits `slac-ssh-mfa:8000` directly | ✅ **Yes — exploitable** | No NetworkPolicy; header passes through untouched to `auth()` |
| Operator with `kubectl exec` or `port-forward` | ✅ **Yes — exploitable** | Direct access to pod port, bypasses nginx |
| Future Ingress route added without `configuration-snippet` | ✅ **Yes — would be exploitable** | Easy to forget; no app-layer backstop |
| nginx ingress controller pod is compromised | ✅ **Yes — exploitable** | App cannot distinguish legitimate proxy from compromised one |

### Key observation: overwrite vs. strip

The nginx config **overwrites** the header with Vouch's value rather than **stripping** the
client-supplied header and then setting a fresh one. These are functionally equivalent for
security because nginx's assignment runs after the auth subrequest. However, the overwrite
pattern means the protection is tightly coupled to the `configuration-snippet` being present —
if it is omitted from a new Ingress, the client-supplied value flows through unmodified.

### `whitelist-source-range` annotations

All five Ingress resources have this line commented out:
```yaml
# nginx.ingress.kubernetes.io/whitelist-source-range: 192.168.0.0/16,10.0.0.0/8,...
```
Uncommenting this (with correct CIDRs) would block external traffic at the Ingress layer for
free, with zero code changes. Worth investigating whether the SLAC CIDR is still correct and
why this was disabled.

---

## Requirements

### Functional Requirements

```
FR-1: A NetworkPolicy restricts ingress to sshkey-service pods to traffic from the
      nginx ingress controller namespace/pods only. All other ingress is denied.
FR-2: When SLACSSH_PROXY_SECRET is set, auth() verifies an X-Proxy-Secret header on every
      request and returns HTTP 401 if the header is absent or does not match.
FR-3: Verification uses secrets.compare_digest to prevent timing-based oracle attacks.
FR-4: When SLACSSH_PROXY_SECRET is not set, auth() behaves exactly as today (no regression).
FR-5: App emits a startup WARNING if SLACSSH_PROXY_SECRET is not configured.
FR-6: .env.example documents SLACSSH_PROXY_SECRET with a clear explanation.
FR-7: README documents the security model: overwrite pattern, NetworkPolicy requirements,
      and why new Ingress rules must include the configuration-snippet.
FR-8: (Nice-to-have) Investigate re-enabling whitelist-source-range on Ingress resources.
```

### Non-Functional Requirements

```
NFR-1: The secret check adds < 1 ms overhead per request.
NFR-2: The SLACSSH_PROXY_SECRET value is never written to logs (not even partially).
NFR-3: The NetworkPolicy must not break existing valid traffic from the nginx ingress controller.
NFR-4: Backward compatibility: deployers who do not set SLACSSH_PROXY_SECRET get a warning
        but the service continues to start and handle requests.
```

### Acceptance Criteria

```
AC-1: Given SLACSSH_PROXY_SECRET=mysecret and a request with X-Proxy-Secret: mysecret,
      auth() returns the username (no exception).
AC-2: Given SLACSSH_PROXY_SECRET=mysecret and a request with X-Proxy-Secret: wrongsecret,
      auth() raises HTTPException(401).
AC-3: Given SLACSSH_PROXY_SECRET=mysecret and a request with no X-Proxy-Secret header,
      auth() raises HTTPException(401).
AC-4: Given SLACSSH_PROXY_SECRET="" (unset), auth() passes through to username-header
      check as before (no 401 from secret check).
AC-5: App startup logs a WARNING containing "SLACSSH_PROXY_SECRET" when it is not set.
AC-6: At no point does any log line contain the value of SLACSSH_PROXY_SECRET.
AC-7: NetworkPolicy manifest passes kubectl apply --dry-run=client.
AC-8: With NetworkPolicy applied in dev: a curl from a non-proxy pod to port 8000 times out
      or is refused; a curl from the nginx ingress controller succeeds.
AC-9: Unit tests cover AC-1 through AC-6.
```

---

## Architecture

### Data Flow (current vs. proposed)

```
CURRENT:

  External attacker (HTTPS)
    │  Remote-User: admin  ← ignored; nginx overwrites it
    ▼
  nginx ingress + Vouch  ──► overwrites Remote-User with authed identity ──► app  ✓ safe

  Internal attacker (cluster pod or kubectl exec)
    │  curl slac-ssh-mfa:8000/list/admin -H "Remote-User: admin"
    ▼
  app  ──► auth() reads header → "admin" → authorised  ✗ EXPLOITABLE

PROPOSED:

  Internal attacker
    │  curl slac-ssh-mfa:8000 ...
    ▼
  NetworkPolicy (CNI)  ──► DROP: not from nginx ingress controller namespace

  nginx ingress controller (legitimate)
    │  Remote-User: alice  (set by configuration-snippet from Vouch)
    │  X-Proxy-Secret: <secret>  (injected from k8s Secret)
    ▼
  app  ──► auth(): compare_digest passes → found_username = "alice" → authorised  ✓
```

### Component Changes

**`app.py`** — module-level additions:
```python
import secrets as _secrets   # stdlib, already available

TRUSTED_PROXY_SECRET: str = os.environ.get('SLACSSH_PROXY_SECRET', '')
```

**`app.py`** — `lifespan()` startup warning:
```python
if not TRUSTED_PROXY_SECRET:
    logger.warning(
        "SLACSSH_PROXY_SECRET is not set — proxy secret verification disabled. "
        "Ensure the reverse proxy overwrites the username header on every request."
    )
```

**`app.py`** — `auth()` function:
```python
def auth(request: Request, user_header: str = USERNAME_HEADER_FIELD):
    if TRUSTED_PROXY_SECRET:
        provided = request.headers.get('X-Proxy-Secret', '')
        if not _secrets.compare_digest(provided, TRUSTED_PROXY_SECRET):
            logger.warning("Proxy secret verification failed — possible header spoofing attempt.")
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing proxy secret.")
    found_username = request.headers.get(user_header)
    ...
```

**`kubernetes/base/networkpolicy.yaml`** — new file:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sshkey-service-ingress
spec:
  podSelector:
    matchLabels:
      app: slac-ssh-mfa          # matches current deployment label
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx   # adjust to actual ingress-controller namespace
      ports:
        - protocol: TCP
          port: 8000
```

> **Note:** Using `namespaceSelector` for the ingress controller is more robust than
> `podSelector` because the ingress controller namespace is stable, whereas pod labels can vary.
> Verify the actual namespace name (`ingress-nginx`, `kube-system`, etc.) before applying.

**`kubernetes/overlays/dev/deployment.yaml`** — add secret ref:
```yaml
env:
  - name: SLACSSH_PROXY_SECRET
    valueFrom:
      secretKeyRef:
        name: sshkey-service-proxy-secret
        key: proxy-secret
```

**`kubernetes/overlays/dev/endpoints.yaml`** — add `proxy_set_header` to `configuration-snippet`
on all auth'd Ingress resources (already present; document that it must stay):
```yaml
nginx.ingress.kubernetes.io/configuration-snippet: |
  proxy_set_header Remote-Name $http_x_vouch_idp_claims_name;
  proxy_set_header Remote-User $http_x_vouch_idp_claims_name;
  proxy_set_header X-Proxy-Secret "<value from k8s Secret>";  # add this
```

### No Migration Required

Purely additive. When `SLACSSH_PROXY_SECRET` is not set, behaviour is identical to today.
NetworkPolicy can be applied independently in dev before touching the app.

---

## ADRs

### ADR-001: NetworkPolicy as the primary fix (not the shared secret)

**Status:** Accepted  
**Date:** 2026-04-07

**Context:** The original plan treated the shared proxy secret as the primary defence and
NetworkPolicy as secondary. After analysing the actual nginx `configuration-snippet` behaviour,
the external attack surface is already closed by the overwrite pattern. The real gap is the
lack of network-layer isolation preventing internal cluster access.

**Decision:** NetworkPolicy is Slice 1 (highest priority) because it closes the actually
exploitable path today. The shared secret (Slice 2) is still worth doing as defence-in-depth
against future Ingress misconfiguration, but it is not the primary fix.

**Consequences:** NetworkPolicy must be tested carefully in dev before prod — a wrong
`namespaceSelector` or `podSelector` will block legitimate nginx traffic and take down the service.

---

### ADR-002: `namespaceSelector` over `podSelector` for ingress controller

**Status:** Accepted  
**Date:** 2026-04-07

**Context:** We could select the ingress controller by pod label or by namespace. Pod labels
on ingress controller pods can vary across nginx-ingress versions; the namespace name is stable.

**Decision:** Use `namespaceSelector: kubernetes.io/metadata.name: ingress-nginx` (or the
correct namespace). This is less brittle and is the recommended pattern in Kubernetes docs.

**Consequences:** Need to confirm the actual ingress controller namespace name in the SLAC cluster.

---

### ADR-003: `secrets.compare_digest` for constant-time comparison

**Status:** Accepted  
**Date:** 2026-04-07

**Context:** Naïve `==` comparison is vulnerable to timing attacks. The secret is short
(likely 32–64 bytes) but constant-time comparison is trivially available and is best practice.

**Decision:** `secrets.compare_digest(a, b)` from stdlib. Zero new dependencies.

---

## Trade-offs

```
Choice: NetworkPolicy namespaceSelector vs. podSelector for ingress controller
  + namespaceSelector: stable; survives pod restarts and label changes
  - namespaceSelector: need to verify the exact namespace name per cluster
  Decision: namespaceSelector; document the lookup command in the README.

Choice: Opt-in shared secret (empty default) vs. mandatory (fail startup)
  + Opt-in: zero-downtime rollout; existing deployments unaffected
  - Opt-in: WARNING can be missed; service runs without the protection indefinitely
  Decision: Opt-in now. Follow-on task to make it mandatory once all deployments migrate.

Choice: Re-enable whitelist-source-range on Ingress resources vs. leave commented out
  + Free IP-layer restriction; no code changes required
  - Need to verify SLAC CIDR is still correct; may block legitimate off-campus access
  Decision: Investigate separately (FR-8); do not block this issue on it.
```

---

## Delivery Slices

### Slice 1 — NetworkPolicy (0.5d) — closes the actively exploitable path

- Add `kubernetes/base/networkpolicy.yaml` with `namespaceSelector` for ingress controller
- Determine correct ingress-controller namespace in the SLAC cluster
- Add to `kubernetes/overlays/dev/kustomization.yaml` resources list
- Verify with `kubectl apply --dry-run=client`
- Test in dev namespace:
  - curl from a non-ingress pod → connection refused / timeout (AC-8)
  - normal browser request through nginx → still works

### Slice 2 — App-layer shared secret (1d) — defence-in-depth

- Add `TRUSTED_PROXY_SECRET` module-level var reading `SLACSSH_PROXY_SECRET`
- Add `secrets.compare_digest` check to `auth()` before username-header lookup
- Emit startup WARNING in `lifespan()` if secret is not set
- Add unit tests `tests/test_auth_header_spoofing.py`:
  - AC-1: correct secret → passes
  - AC-2: wrong secret → 401
  - AC-3: missing header → 401
  - AC-4: unset secret → passes through
  - AC-5: startup warning emitted when unset
  - AC-6: secret value absent from all log output
- Update `.env.example` with `SLACSSH_PROXY_SECRET=`
- Update `kubernetes/overlays/dev/deployment.yaml` with `secretKeyRef`
- Add `X-Proxy-Secret` injection to the `configuration-snippet` in `endpoints.yaml`

### Slice 3 — Docs (0.5d)

- Update `README.md` — add "Security Model" section covering:
  - The overwrite pattern (not strip) and why it works
  - Why every new Ingress resource must include `configuration-snippet`
  - `SLACSSH_PROXY_SECRET` setup instructions
  - NetworkPolicy label/namespace requirements and how to find them
  - The `whitelist-source-range` situation and follow-up action

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| NetworkPolicy blocks nginx ingress controller (wrong namespace label) | Medium | High | Dry-run in dev; test before prod; document lookup command |
| New Ingress rule added without `configuration-snippet` | Medium | High | Document requirement in README; note in Ingress template comments |
| Proxy not updated to inject `X-Proxy-Secret` | Medium | Medium | Default is disabled; startup WARNING; document clearly |
| Secret leaked via env var | Low | High | Use k8s Secret object; never log the value |
| Operators ignore startup WARNING permanently | Medium | High | Follow-on task: make secret mandatory at startup |
| `whitelist-source-range` re-enabled with stale CIDR | Low | Medium | Verify CIDRs before uncommenting; treat as separate change |

---

## Definition of Done

- [ ] NetworkPolicy manifest added to `kubernetes/base/` and included in dev overlay
- [ ] Correct ingress-controller namespace confirmed and documented
- [ ] `kubectl apply --dry-run=client` passes on NetworkPolicy
- [ ] NetworkPolicy tested in dev: non-ingress pod blocked, browser traffic passes
- [ ] `auth()` verifies `X-Proxy-Secret` via `secrets.compare_digest` when `SLACSSH_PROXY_SECRET` is set
- [ ] Startup emits WARNING if `SLACSSH_PROXY_SECRET` is not configured
- [ ] WARNING never includes the secret value
- [ ] Unit tests cover AC-1 through AC-6 and all pass
- [ ] `deployment.yaml` updated with `secretKeyRef` for `SLACSSH_PROXY_SECRET`
- [ ] `endpoints.yaml` updated: `X-Proxy-Secret` injection added to `configuration-snippet` on all auth'd Ingress resources
- [ ] `.env.example` updated with `SLACSSH_PROXY_SECRET=`
- [ ] README "Security Model" section added
- [ ] No new external dependencies added
