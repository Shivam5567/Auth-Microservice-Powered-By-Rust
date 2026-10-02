# Auth microservice

A Rust authentication service: registration, login, access tokens, and refresh
token rotation with reuse detection. Built as the first service in a Cargo
workspace that is meant to hold more.

## What it does

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/v1/auth/register` | – | Create an account, returns the profile |
| `POST` | `/api/v1/auth/login` | – | Returns an access/refresh pair |
| `POST` | `/api/v1/auth/refresh` | – | Rotates the refresh token, returns a new pair |
| `POST` | `/api/v1/auth/logout` | – | Ends one session, or all with `all_devices` |
| `GET` | `/api/v1/auth/me` | Bearer | The caller's profile and roles |
| `GET` | `/admin/` | – | The admin panel page |
| `GET` | `/health` | – | Liveness |
| `GET` | `/health/ready` | – | Readiness, checks the database |

## The admin panel

A single page at `/admin/` for managing the downstream services that consume
this one. No frontend build step: the HTML is embedded in the binary and talks
to the admin API with plain `fetch`.

Every admin route needs a token carrying the `admin` role, which you paste into
the panel. To get the first one, set `ADMIN_BOOTSTRAP_EMAILS` to your own
address before registering, then clear it once you exist:

```sh
ADMIN_BOOTSTRAP_EMAILS=you@example.com docker compose up -d
# register you@example.com, then log in and paste the token into the panel
```

The API behind it, all under `/api/v1/admin/services` and all `admin`-gated:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | List, with optional `status`, `search`, `limit`, `offset` |
| `GET` | `/summary` | Counts for the header |
| `GET` | `/events` | Recent admin activity |
| `GET` | `/{name}` | One service |
| `POST` | `/` | Register a service |
| `PATCH` | `/{name}` | Edit description and scopes |
| `DELETE` | `/{name}` | Remove it, revoking its live tokens |
| `POST` | `/{name}/restore` | Bring it back |

Names are normalised to a lowercase slug, so `Billing API` becomes
`billing-api` and cannot be registered twice under a different spelling.

### Removal is revocation, not just a status change

A service carries a `token_version` that is stamped into any access token minted
for it. Removing the service disables it and bumps that version, so tokens
already in flight stop verifying on the next request rather than lingering until
they expire. Restoring bumps it again, which is why a token issued before a
removal does not come back to life.

Sessions are pinned to the service they were opened for, including across
refresh rotation. A decommissioned service therefore cannot be kept alive by
exchanging a refresh token, and a refreshed token cannot escape the
revocation.

Tokens issued *without* naming a service are deliberately unaffected: they
belong to no single downstream service, so removing one service should not log
everyone out.

Removal is a soft delete. The row and its history stay, and `restore` brings it
back. Every change is appended to `service_events` with the acting admin.

## How the security works

**Access tokens are RS256 JWTs.** Only this service holds the private key.
Other services verify tokens with the public key alone, so a compromise
elsewhere cannot mint new identities. The keypair is generated on first run
from `JWT_PRIVATE_KEY_PATH` and `JWT_PUBLIC_KEY_PATH`.

**Refresh tokens are opaque, not JWTs.** Each is 256 bits of randomness,
base64url encoded, and only its SHA-256 digest is stored. That is what makes
server-side revocation possible; a self-contained refresh token could not be
withdrawn before it expired.

**Refresh tokens rotate, and replay is fatal.** Every login starts a token
family. Exchanging a token issues a new one in the same family and marks the
old one used. Presenting an already-used token means either the client replayed
something stale or someone stole it, so the entire family is revoked and a
fresh login is required. The exchange is a single conditional `UPDATE`, so two
concurrent requests cannot both win.

**Passwords use Argon2id** at 19 MiB, 2 iterations, 1 lane, with a per-password
salt. A failed login spends the same CPU whether or not the account exists, so
timing does not disclose which addresses are registered.

**Signing out everywhere kills live tokens.** `users.token_version` is embedded
in every access token, so bumping it invalidates tokens that have not yet
expired.

**Logging in for a service.** `login` accepts an optional `service` field. When
set, the returned tokens are bound to that service and die when it is removed.
Naming a service that is not registered is a 400, and one that has been
decommissioned is a 403, rather than quietly falling back to an unbound token.

**Auth routes are throttled per client IP** (10/minute by default). A 429 comes
back in the same JSON envelope as every other error.

## Errors

Every failure is the same shape, and internal detail never reaches the caller:

```json
{
  "error": {
    "code": "unauthorized",
    "message": "invalid or expired access token"
  }
}
```

`message` is safe to show a user. Database and filesystem detail goes to the
log instead, correlated by the `x-request-id` response header, which is echoed
from the request or minted if absent.

## Running it

With Docker, which also gives you a real Postgres:

```sh
cp .env.example .env
docker compose up --build
curl localhost:8080/health
```

`POSTGRES_PORT` and `AUTH_PORT` in `.env` control the host-side ports only; the
service always listens on 8080 inside its container. They default to 5433 and
8080 to avoid colliding with a Postgres you may already run locally.

Tear down with `docker compose down`, or add `-v` to discard the database and
the stored signing keys.

Without Docker, point `DATABASE_URL` at a Postgres you already have and:

```sh
cargo run -p auth-service
```

Migrations run on startup unless `RUN_MIGRATIONS=false`.

### Try the flow

```sh
curl -s localhost:8080/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'

curl -s localhost:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'

curl -s localhost:8080/api/v1/auth/me -H "authorization: Bearer $ACCESS_TOKEN"
```

## Tests

```sh
cargo test --workspace
```

Unit tests cover password hashing, token signing and verification, the rotation
state machine, the rate limiter, and config parsing. The integration suite in
`services/auth-service/tests/` drives the API over HTTP against a real Postgres
in a container, including the token-theft case, and asserts that neither the
password nor the refresh token is ever stored in the clear.

The integration tests need a running Docker daemon. Each test starts its own
Postgres container and drops it again, so containers are not left behind;
they are slow, so run them with a few threads:

```sh
cargo test --workspace -- --test-threads=4
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Layout

```
crates/common/            error envelope and tracing, shared by every service
services/auth-service/    the service itself
  migrations/             SQL, embedded into the binary at compile time
  src/domain/             password, keys, claims, tokens — no I/O
  src/db/                 repositories
  src/service/            use cases, where the token lifecycle lives
  src/http/               handlers, routes, middleware
  tests/                  integration suite
```

The domain layer has no database or HTTP knowledge, which is what lets the
security rules be tested directly.

## Notes for the next service

Add the crate to the workspace `members` list and put anything genuinely common
in `crates/common`. Resist moving things there early; a shared crate that
collects every team's helpers is worse than a little duplication.

For services to verify access tokens, distribute `keys/public.pem` to them and
have them check `iss`, `aud` and `exp`. A JWKS endpoint is not implemented
because `jsonwebtoken` can consume but not emit a JWK, so it would need the
public key's `n` and `e` extracted by hand. Worth doing if key rotation across
services becomes a requirement.
