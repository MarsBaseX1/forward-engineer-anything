# FEA authorization reference — NOT production authentication

A separate loopback-only HTTP reference (`src/auth-demo.mjs`) illustrates the distinction between **client state** and **server-side authorization**. It is not connected to the audit CLI and must not be deployed to the public internet.

Run `npm run auth:demo`. The example starts on `127.0.0.1` using an ephemeral port, issues one cryptographically random 256-bit opaque bearer capability *inside the server process*, and tests one allowed and one cross-tenant operation. The token is never logged. No HTTP token-issuance endpoint exists.

A grant is held server-side with subject, tenant, resource, action, expiration, revocation and per-token quota. `POST /perform` checks those fields independently of any `premium` or `subject` values asserted by the client. Negative tests cover wrong tenant, resource, operation, revoked/expired grant, exhausted quota, missing bearer and oversized request.

The demo has **no real user registration, TLS, identity provider, durable database, audit trail, distributed quota, key rotation or token theft defense**. Production implementations should adopt established OAuth/OIDC frameworks, managed secrets and persistent authorization state; do not treat this example as a production security template.
