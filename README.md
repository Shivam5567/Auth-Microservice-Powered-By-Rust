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

## The example storefront

`services/orders-service` is a small e-commerce API that consumes the auth
service. It is here to be read: the commerce is trivial, the integration is the
point.

```
docker compose up --build -d
# then open http://localhost:8082/shop/
```

`orders-service` holds its own database. The only thing it shares with the auth
service is the user's UUID — no shared schema, and deliberately no foreign key
across the boundary, because the two have no common transaction and coupling
them would turn an auth-side outage into an orders-side one.

### How a request becomes an identity

`auth.rs` is the module worth copying. It offers two strategies, chosen by
`TOKEN_CHECK`:

| Mode | What it does | Latency | Sees revocations |
| --- | --- | --- | --- |
| `local` (default) | Verifies the RS256 signature with the auth service's public key, fetched once and cached | No network hop | **No** |
| `introspect` | Calls `/api/v1/auth/me` on every request | One hop per request | Yes, immediately |

Local verification is the normal microservices pattern, and it is what signing
with RS256 instead of a shared secret buys you: `orders-service` holds a
*public* key, so it can check a token without being able to mint one, and
without calling the issuer. The cost is real, though — it cannot see a token the
issuer has since withdrawn, because a signature is still a valid signature.

The two modes differ in exactly one observable way, and you can see it:

```sh
# With TOKEN_CHECK=local
curl -X DELETE localhost:8081/api/v1/admin/services/orders-service \
  -H "authorization: Bearer $ADMIN"
# refresh and new sign-ins are refused immediately
# but tokens already issued keep working at orders-service until they expire
```

That 15-minute window is the trade. `introspect` closes it at the cost of a
network hop on every request and the issuer on your hot path. For a storefront
like this, `local` with 15-minute tokens is the reasonable default; for
something handling payments, `introspect` is worth the latency.

### Where the refresh token lives

`cookie.rs`. It is an `httpOnly` cookie scoped to `Path=/api/auth`, which means
it is invisible to JavaScript and does not ride along on order requests. The
access token is the only thing handed to the page, and it is held in memory
there.

### The trap: concurrent refreshes

Refresh tokens rotate, and the auth service treats a second use of one as
theft — it revokes the whole token family. So three requests that refresh at the
same instant will sign the user out.

The storefront demonstrates both behaviours. Open `/shop/`, sign in, then press
**"Place 3 orders at once"** with **"Naive client"** unticked: the three
requests share one refresh and all succeed. Tick the box and press it again: the
losing refreshes burn the session and you are signed out.

The fix is single-flight, and it is about ten lines:

```js
var inFlight = null;
function refreshOnce() {
  if (!inFlight) {
    inFlight = doRefresh().finally(() => { inFlight = null; });
  }
  return inFlight;
}
```

### What belongs to whom

The auth service answers "who is this". Everything else is `orders-service`'s
job, and it has one rule worth copying: a customer asking for someone else's
order gets **404, not 403**, because a 403 confirms the order exists.

```
GET /api/catalog                  public
POST /api/auth/login              proxies to the auth service, sets the cookie
POST /api/auth/refresh            rotates the session
POST /api/auth/logout             revokes the session
GET  /api/auth/whoami             who am I, and how you worked it out
POST /api/orders                  place an order
GET  /api/orders                  your orders, or everyone's with all=true
GET  /api/orders/{id}             your order, or anyone's as an admin
POST /api/orders/{id}/refund      admin only
```

Order totals are computed from the server's catalogue, never taken from the
request, so a client cannot name its own price.

## Tests

Three layers, depending on what you want to know.

**1. Automated, no running service**

```sh
cargo test --workspace -- --test-threads=4
```

Unit tests cover password hashing, token signing and verification, the rotation
state machine, the rate limiter, name normalisation, and config parsing. The
integration suites in `services/auth-service/tests/` and
`services/orders-service/` drive the real APIs against a real Postgres in a
container, including the token-theft case, and assert that neither the password
nor the refresh token is ever stored in the clear.

These need a running Docker daemon. Each test starts and drops its own
container, so nothing is left behind; they are slow, so run them with a few
threads.

**2. Against a running stack**

```sh
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build -d
./scripts/smoke-test.ps1            # the auth service alone, 44 checks
./scripts/integration-test.ps1      # the storefront on top of it, 29 checks
```

The first covers the auth service's own surface: the auth flow, validation,
rotation, the theft case, the admin registry, and that removing a service
revokes its tokens. The second drives the real integration: signing in through
the storefront, the refresh cookie, order ownership, the role gates, and the
two token strategies. Both exit non-zero on failure, so they work as gates.

The test override exists for one reason: these scripts are a single client
making far more requests than a human would, so the production limit of 10 per
minute would throttle them into a wall of 429s that proves nothing. Every
security behaviour is unchanged.

```sh
./scripts/smoke-test.ps1 -BaseUrl http://localhost:8080
```

**3. Exploring it yourself**

The storefront at `http://localhost:8082/shop/` is the fastest way in. Sign in,
place an order, then tick **"Naive client"** and press **"Place 3 orders at
once"** to watch refresh-token rotation punish a client that does not
single-flight.

To see revocation across services:

```sh
ADMIN=$(curl -s localhost:8081/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"boss@example.com","password":"correct horse battery staple"}' \
  | jq -r .access_token)

curl -s -X DELETE localhost:8081/api/v1/admin/services/orders-service \
  -H "authorization: Bearer $ADMIN"
```

Existing sessions stop refreshing and cannot sign in again. With
`TOKEN_CHECK=local` an already-issued access token keeps working at
`orders-service` until it expires; with `TOKEN_CHECK=introspect` it is refused
on the next request.

**Linting**

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

**Looking at what is stored**

```sh
docker compose exec postgres psql -U auth -d auth     -c "SELECT email, left(password_hash, 30) FROM users;"
docker compose exec postgres psql -U auth -d orders   -c "SELECT name, status, token_version FROM services;"
docker compose exec postgres psql -U auth -d orders   -c "SELECT id, status, total_cents FROM orders;"
```

## Layout

```
crates/common/            error envelope and tracing, shared by every service
services/auth-service/    the auth service
  migrations/             SQL, embedded into the binary at compile time
  src/domain/             password, keys, claims, tokens — no I/O
  src/db/                 repositories
  src/service/            use cases, where the token lifecycle lives
  src/http/               handlers, routes, middleware
  assets/admin.html       the admin panel
  tests/                  integration suite
services/orders-service/  an example consumer
  src/auth.rs             ← the auth client and the two check modes
  src/cookie.rs           ← where the refresh token lives
  src/caller.rs           the extractor every protected handler takes
  assets/index.html       the demo storefront
```

The domain layer has no database or HTTP knowledge, which is what lets the
security rules be tested directly.

## Notes for the next service

Add the crate to the workspace `members` list and put anything genuinely common
in `crates/common`. Resist moving things there early; a shared crate that
collects every team's helpers is worse than a little duplication.

`orders-service` shows what a second service actually needs: its own database,
its own migrations, its own Dockerfile, and one module that talks to the auth
service. It shares no claims types with the issuer on purpose — see the note in
`auth.rs` about why a service boundary is a contract.

For services to verify access tokens, they fetch `/public-key` from the auth
service and cache it; the key is cached for five minutes and refetched on
verification failure, so a rotation is picked up without a restart. A JWKS
endpoint is not implemented because `jsonwebtoken` can consume a JWK but not
emit one, so it would need the public key's `n` and `e` extracted by hand. Worth
doing if you add many services or rotate keys often.
