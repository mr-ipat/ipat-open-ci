# IPAT R6.5 — Customer MikroTik access options and live-safety preflight

**Developer:** Mr. iPat
**Status:** First physical customer-router login and actual configuration **NOT DONE**.
**Previous source:** R6.4 restricted first SSH read (merged main).

## One exact operator-authorized endpoint: observations

The owner authorizes temporary SSH password use, or alternatively API-SSL
or MikroTik TR-069, for one customer RB951Ui-2HnD reportedly on
RouterOS 7.23.7. This is approval to **prepare** a narrow laboratory
session, not proof that the network endpoint presents the expected
physical device. No supplied password, real endpoint, raw fingerprint
or device secret is copied into this document or repository.

The previously observed remote RSA SSH host-key change **persists**.
One specific public SSH port accepts TCP, but current and historical
host RSA keys differ. A service banner alone does not establish hardware
identity or eliminate the risk of changed forwarding destination.
The existing R6.3/R6.4 fail-closed procedures remain mandatory.

An additional unauthenticated, exact-target two-port check from the
authorized Mac found no verified-reachable service on the usual
API-SSL port or the normal HTTPS port. This is **not proof** that
these services are disabled on the real router: NAT, source firewall,
nonstandard port mapping or topology may differ. No service
authentication, router config change or live firmware interrogation
occurred.

TR-069 is not a drop-in replacement for an authenticated router
management connection. MikroTik uses the separate `tr069-client`
package, and the client must be independently configured to contact
an authenticated, TLS-verifiable ACS endpoint. IPAT's native ACS
has not been exposed or approved as a production customer endpoint;
no new WAN listener, external firewall rule or customer Inform
schedule is authorized in this milestone.

## Approved narrow first-probe choice

Use the existing SSH listener ONLY after independent trusted direct-LAN
verification of the actual customer router's current RSA host key.
Do not accept a public-key scan of the same public network path as
independent evidence. Preserve the existing owner Mac known_hosts
record; R6.4 can create a temporary strict exact-endpoint host key
pin *only* after review of the independent LAN proof.

The owner Mac already contains a **new distinct** customer lab RSA
private/public key pair under its private
`~/.local/share/ipat/router-lab/` directory. The local private
key is owner-only; the corresponding *.pub file may be installed
on a dedicated, explicitly restricted RouterOS account from an
independently trusted WinBox or local console session.
Never paste or upload the private key. Do not grant the new
account generic administrator, `full`, built-in `read`
or extra-sensitive/reboot policy rights.

For an authorized trusted WinBox operator: first verify actual
board model/version and that the expected physical device is selected;
back up the router independently and confirm tested non-disruptive
recovery. Then create a **new** custom group limited to
SSH-login plus read permission, attach a distinct temporary account
restricted to the actual authorized management-client source address,
and install the existing public key for that account.
Do not change the current SSH service port, active routes,
NAT, provider firewall, input filter order or customer interface.
Keep an independently reviewed removal plan that removes only
the newly created lab account and group.

Existing R6.4 `--preflight` checks owner-private config, independently
trusted LAN RSA fingerprint, dedicated private key, exact model/version,
verified backup/recovery and explicit consent without network.
Its single remote read requires three explicit local opt-ins,
RSA SHA-2 strict host validation and outputs unreviewed, redacted
inventory only. No password from chat is injected into the adapter.

## API-SSL and TR-069 are later, separately gated alternatives

API-SSL uses a distinct **binary API**, not the already coded
R6.1 HTTPS REST helper (which requires `www-ssl`).
Only consider API-SSL after a private source-restricted path,
a certificate chain and expected TLS server identity are
independently verified and its adapter is reviewed.
Do not enable anonymous TLS modes or expose it over public WAN.

Before a TR-069 pilot, verify that the actual router has the
exact matching enabled `tr069-client` package, prepare a separate
test ACS listener and trusted certificate, record isolated scope,
confirm customer consent, then manually configure the client through
trusted management. Do not assume TR-069 is active on RouterOS
just because the base firmware is owner-reported.

## Acceptance and next dependency

Current status remains **physical router unconnected/unverified,
zero customer devices enrolled and zero write operations**. Actual
physical work requires independent device identification in a
trusted local WinBox session, current SSH fingerprint evidence
through that trusted path, a non-disruptive verified backup,
a restricted new account and source-limited management.
A password-authenticated SSH login to an unexpectedly changed host
without that evidence is not an acceptable workaround.
