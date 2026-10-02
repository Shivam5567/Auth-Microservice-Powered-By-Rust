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

## Testing by hand

Three layers, depending on what you want to know.

**1. Automated, no running service**

```sh
cargo test --workspace -- --test-threads=4
```

Unit tests cover password hashing, token signing and verification, the rotation
state machine, the rate limiter, name normalisation, and config parsing. The
integration suites in `services/auth-service/tests/` drive the API over HTTP
against a real Postgres in a container, including the token-theft case, and
assert that neither the password nor the refresh token is ever stored in the
clear. Each test starts and drops its own container, so nothing is left behind.

**2. Smoke test against a running service**

```sh
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build -d
./scripts/smoke-test.ps1
```

44 checks across the whole surface: the auth flow, input validation, token
rotation, the theft case, the admin registry, and that removing a downstream
service really does revoke its tokens. Exits non-zero on failure, so it works
as a gate.

The test override exists for one reason: the smoke test is a single client
making far more requests than a human would, so the production limit of 10 per
minute would throttle it into a wall of 429s that proves nothing. Every security
behaviour is unchanged.

```sh
./scripts/smoke-test.ps1 -BaseUrl http://localhost:8080
```

**3. Exploring it yourself**

Worth doing once, because it shows what the numbers mean:

```sh
# Get a token
TOKEN=$(curl -s localhost:8081/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct horse battery staple"}' \
  | jq -r .access_token)

curl -s localhost:8081/api/v1/auth/me -H "authorization: Bearer $TOKEN"
```

Then the part worth trying. Register a downstream service, log in bound to it,
then remove it and watch the same token die:

```sh
# Needs a token carrying the admin role
curl -s -X POST localhost:8081/api/v1/admin/services \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"Billing API","scopes":["orders:read"]}'

BOUND=$(curl -s localhost:8081/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"correct horse battery staple","service":"Billing API"}' \
  | jq -r .access_token)

curl -s -o /dev/null -w '%{http_code}\n' localhost:8081/api/v1/auth/me \
  -H "authorization: Bearer $BOUND"          # 200

curl -s -X DELETE localhost:8081/api/v1/admin/services/billing-api \
  -H "authorization: Bearer $TOKEN" > /dev/null

curl -s -o /dev/null -w '%{http_code}\n' localhost:8081/api/v1/auth/me \
  -H "authorization: Bearer $BOUND"          # 403, immediately
```

The admin panel at `/admin/` is the same thing with buttons.

To look at what is actually stored, while the stack is up:

```sh
docker compose exec postgres psql -U auth -d auth -c "SELECT email, left(password_hash, 30) FROM users;"
docker compose exec postgres psql -U auth -d auth -c "SELECT name, status, token_version FROM services;"
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
