# Threat model and security design

## Boundary and assets

The trusted local operator owns the process, SQLite database and key file. The simulated untrusted party is an application identity attempting actions through `Lab.login` and `Lab.act`. Protect fictional sample confidentiality, result integrity, account sessions and audit accountability against unauthorized application actions. No real institution or external target is accessed.

This is a CLI and callable Python core, not a network service. A hostile OS user with the same filesystem privileges can bypass the application. The `provision`, `events`, `verify` and research functions are local administrative APIs, not remote endpoints. Do not expose them as HTTP routes without a separate security design.

## Controls and evidence

| Threat | Control | Validation |
|---|---|---|
| Role escalation | Explicit role/action matrix; deny unknown actions | Complete implemented role/action matrix test |
| Cross-project sample access | Per-object project comparison; scoped export query | Cross-project read denial and export-scope test |
| Forged or stale session | Random 32-byte opaque tokens, hashed token storage, 15-minute expiry, logout revocation | Invalid, expired and revoked token tests |
| Password guessing | Per-user salted scrypt hash; temporary lockout after five failures | Lockout test |
| SQL injection | Parameterized data queries | Injection-string lookup denied |
| Audit edit / middle deletion | Sequenced HMAC-SHA256 chain | Payload tamper test |
| Audit suffix truncation | Independently retained chain head | Trusted-checkpoint test |
| Write succeeds without audit | One SQLite immediate transaction for change and audit | Forced audit failure rolls back sample update |
| Secrets in logs | No password, session token or result body logged | Secret-exclusion test |

Passwords use scrypt N=16384, r=8, p=1 and unique 16-byte salts. This demonstrates salted password hashing; it is not a claim that these work factors meet every current production recommendation. Tune using current guidance and measured deployment resources. Five failed logins cause a 60-second account lock; repeated failures can extend it, enabling denial of service. There is no distributed rate limiter or MFA.

Audit events record sequence, UTC timestamp, actor, action, outcome, project and record count. JSON encoding prevents newline text from becoming independent structured records. Unknown actor/action text is length-bounded. State changes and log appends share a transaction; failed logging prevents returning successful access results. Verification happens explicitly and before offline scoring, not before every request. Ordinary startup does not automatically reject a damaged audit history.

The HMAC key is separate from SQLite but colocated under the same trusted OS owner. This is **tamper evidence, not immutable storage**. An attacker with the key can forge a chain. Without an independent checkpoint, a valid prefix is indistinguishable from a truncated log. Keys and database files are excluded by `.gitignore`; do not use real data or credentials. There is no key rotation, external log collector, WORM storage, backup verification or remote attestation.

## Scientific workflow limitations

Two fictional records demonstrate scoped access; they are not a complete LIMS. No versioned result history, electronic signatures, instrument provenance, approval workflow, study consent, inventory, quality-control validation, retention policy or regulatory certification is implemented. The global auditor can see project and actor metadata. Integrity checking does not prove the scientific truth of a recorded result. Availability under load, concurrent process behavior and recovery from crashes were not benchmarked.
