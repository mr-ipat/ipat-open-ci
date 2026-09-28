# IPAT R5.9 — private browser preview on the owner's Mac

**Developer:** Mr. iPat
**Scope:** Read-only interface for existing Rust Control API, available exclusively
through local SSH forwarding. **This is not a commercial SaaS tenant dashboard.**

## 1. Delivered browser experience and non-goals

- `web/lab/index.html`, `style.css`, `app.js`: responsive Indonesian
  read-only project laboratory console. No third-party CDN or analytics.
- `apps/control-api/src/main.rs`: existing Rust/Tokio/Axum app includes HTML,
  stylesheet, JS and a minimal static no-customer-data status endpoint. The
  preview is disabled by default and only enabled by `IPAT_LAB_WEB=1` **when
  K3s wildcard pod binding is disabled**. Container Helm manifests are unchanged:
  K3s lab apps still have NO web UI, no public service, no OIDC bypass.
- Enforces CSP default-deny, first-party CSS/JS/status only, no forms,
  no session/cookie/token data, no secret values, no caching, denied framing,
  denied direct device data endpoint and denied all mutation routes. The
  lab status JSON reports `production_access=false`,
  `authentication_enabled=false` and `device_operations_enabled=false`.
- R5.8's synthetic USP Controller stub is NOT a real MQTT/USP transport;
  its status is a static, clearly labelled laboratory capability.
  Rendered K3s and CI achievements are historical test evidence, not live
  Kubernetes/DB telemetry or an active subscriber inventory.
- No external provider firewall integration, DNS modifications, new TCP/443
  public listener, shared Security Group change, host firewall or K3s install.

## 2. Browser access, opt-in and teardown

Run only on the **authorized Mac** with its existing verified `ipat-lab`
SSH host alias, an existing repository whose *clean main* matches the private
GitHub and non-root Ubuntu 26.04.1 source, and FileVault enabled.

```bash
cd ~/Projects/ipat-current
IPAT_R59_ENABLE_PRIVATE_WEB=YES \
  bash deploy/scripts/lab/r59/start-private-web-mac.sh
# Only AFTER the helper independently reports its two PASS markers:
open http://127.0.0.1:48765/lab
```

The helper does all of the following in one fail-closed sequence: compares
reviewed Git SHA with private GitHub and the actual VPS's nonprivileged source;
checks no pending SSH rollback; compiles ONLY the original Rust Control API
using the VPS's **locked, offline** Rust cache; starts an unprivileged
`127.0.0.1:3000` process with the explicit local-preview flag; confirms
the actual listener is not wildcard; verifies minimal JSON flags; opens a
strict-known-host key-only SSH tunnel **bound only to the Mac's
`127.0.0.1:48765`**; verifies end-to-end local JSON and HTML over that
tunnel. No sudo or external ingress change is permitted. It refuses port
conflicts or mismatched stale PID/service identities instead of killing an
unknown process. Logs and known PID/source marker are mode-restricted in
the user's `~/.cache/ipat-private-web`, never in Git.

The private preview URL **cannot** be accessed on other devices, from a
public IP, or while the Mac is offline. This local `http://` URL is safe
only because it is restricted to the owner's loopback and traverses the
authenticated, encrypted SSH connection. Never direct other computers to
access the loopback URL. If SSH/Mac shuts down, rerun the start helper.

Stop only this temporary service and this precisely tracked Mac tunnel:

```bash
cd ~/Projects/ipat-current
IPAT_R59_STOP_PRIVATE_WEB=YES \
  bash deploy/scripts/lab/r59/stop-private-web-mac.sh
```

Do not expose this unauthenticated preview through any reverse proxy,
NodePort, Ingress, public DNS, tunnel-sharing provider or port-forward
to a non-loopback interface. It is NOT a login portal.

## 3. Acceptance and test evidence

- `python3 -m unittest discover deploy/scripts/lab/r59 -p 'test_r59_review.py' -v`
  checks default route denial, K3s mode guard, restrictive headers, HTML,
  script local-only behavior, no privileged deployment changes and launcher
  negative path on non-opt-in environments.
- Actual isolated **nonprivileged Ubuntu 26.04.1** checkout must run
  `cargo fmt --all -- --check` and
  `cargo test --workspace --locked --offline` before feature merge.
- A temporary real loopback server must actually serve `/lab`, stylesheet,
  JS and valid no-customer-data `/lab/status`. Independently check CSP,
  401 on anonymous `/v1/devices/synthetic`, 405 on attempted status POST,
  and sampled `ss` listener **only** `127.0.0.1:3000`.
- Real GitHub PR and post-merge main CI, final synchronized SHA, new encrypted
  exact-commit Restic backup and separate selected-root configuration
  restoration must be recorded. The final Mac browser-tunnel smoke must run
  only AFTER the reviewed source is merged.
- Actual HTML/browser layout has not been visually inspected with a screenshot
  by CI; HTTP and source-level tests are not a browser-rendering assertion.

## 4. Public website production gates

The target company's real public domain, TLS/automated certificate renewal,
identity/OIDC+MFA, verified tenant-domain mapping, menu-level RBAC+ABAC
AND backend/data-plane authorization, production PostgreSQL HA/PITR, secure
network ingress and deployed K3s still require independent implementation,
threat tests and formal acceptance. Actual out-of-band console login, complete
independently restorable live-host recovery, dedicated **effective IPv4 and
IPv6** perimeter and approved ADR-017/018 remain blocked. An operational
local web preview is **not evidence** that any of these external gates passed.

See `docs/PROJECT_STATUS.md` for dated milestone evidence. Do not claim
public website readiness until a real, authorized, identity-protected URL has
been independently checked from an external client.

## R5.9 reviewed feature source proof (pre-docs-merge)

- [PR #49](https://github.com/mr-ipat/ipat/pull/49) merged to private main
  `466ffcb67a87ba3f88330f26a13cebda5d624e7d`; actual GitHub four-job
  PR CI `36210434210` SUCCESS, including disposable Ubuntu 26.04 real K3s
  and synthetic PostgreSQL jobs. The new UI is opt-in only under SSH loopback,
  never deployed as public K3s ingress.
- On actual unchanged Ubuntu VPS with this feature source, Rust format and
  **81/81 locked offline Rust tests**, **42+6+6+6 lab static**,
  **14 DB static** and **5 production gate static** tests PASS; K3s,
  PostgreSQL and nftables remain INACTIVE. Independent real temporary
  nonprivileged private HTTP smoke proved HTML/JS/CSS, CSP, status flags,
  anonymous 401, unsupported POST 405 and exclusive `127.0.0.1:3000`
  listener, with test process subsequently cleaned up.
- Mac FileVault ON; encrypted reviewed-feature-source Restic snapshot
  `8c40ccec` and historical selected privileged-root config snapshot
  `abaa9827` independently recovered with full Restic pack read PASS,
  plaintext test restores removed. Real Mac tunnel and final exact
  documentation-merge source backup need fresh execution and reporting.
  Post-feature-main CI `36210550883` independently returned SUCCESS for
  all four jobs. Final tunnel evidence and docs-only merge/source backup
  remain pending at this checkpoint. Neither provides production
  login/domain/OOB/DB HA readiness.
