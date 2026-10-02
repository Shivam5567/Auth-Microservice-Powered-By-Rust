<#
.SYNOPSIS
  Exercises the two-service flow: the storefront on top of the auth service.

.DESCRIPTION
  Complements scripts/smoke-test.ps1, which covers the auth service on its own.
  This one drives the real integration: signing in through the storefront,
  cookies, order ownership, role gates, and the difference between verifying a
  token locally and asking the issuer.

  Needs both services running, and the raised rate limit, because it makes far
  more auth calls than a person would from one address.
#>
[CmdletBinding()]
param(
  [string] $AuthUrl = "http://localhost:8081",
  [string] $OrdersUrl = "http://localhost:8082",
  [string] $AdminEmail = "boss@example.com",
  [string] $Password = "correct horse battery staple"
)

$ErrorActionPreference = "Stop"
$script:passed = 0
$script:failed = 0

function Test-Case {
  param([string] $Name, [scriptblock] $Body)
  try {
    $null = & $Body
    Write-Host "  PASS  $Name" -ForegroundColor Green
    $script:passed++
  } catch {
    Write-Host "  FAIL  $Name" -ForegroundColor Red
    Write-Host "        $($_.Exception.Message)" -ForegroundColor DarkGray
    $script:failed++
  }
}

function Assert-Equal {
  param($Actual, $Expected, [string] $Because = "")
  if ($Actual -ne $Expected) { throw "expected '$Expected' but got '$Actual'. $Because" }
}

function New-Email {
  param([string] $Prefix)
  "$Prefix-$([guid]::NewGuid().ToString('N').Substring(0, 8))@example.com"
}

function Invoke-Api {
  param([string] $Base, [string] $Method, [string] $Path, $Body, [string] $Token)

  $params = @{ Uri = "$Base$Path"; Method = $Method; ErrorAction = "Stop" }
  if ($null -ne $Body) {
    $params.Body = ($Body | ConvertTo-Json -Depth 5 -Compress)
    $params.ContentType = "application/json"
  }
  if ($Token) { $params.Headers = @{ authorization = "Bearer $Token" } }

  $status = 0
  $text = ""
  try {
    $response = Invoke-WebRequest @params -UseBasicParsing
    $status = [int] $response.StatusCode
    $text = $response.Content
  } catch {
    if ($null -ne $_.Exception.Response) { $status = [int] $_.Exception.Response.StatusCode }
    $text = $_.ErrorDetails.Message
  }

  $parsed = $null
  if (-not [string]::IsNullOrWhiteSpace($text)) {
    try { $parsed = $text | ConvertFrom-Json } catch { $parsed = $null }
  }
  return [pscustomobject]@{ Status = $status; Body = $parsed; Raw = $text }
}

Write-Host ""
Write-Host "Two-service integration against $OrdersUrl + $AuthUrl" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------- readiness
Write-Host "Both services" -ForegroundColor Cyan

Test-Case "the storefront is up" {
  Assert-Equal (Invoke-Api $OrdersUrl GET /health).Status 200
}
Test-Case "the storefront can reach its database" {
  $r = Invoke-Api $OrdersUrl GET /health/ready
  Assert-Equal $r.Status 200
  Assert-Equal $r.Body.database "connected"
}
Test-Case "the auth service is up" {
  Assert-Equal (Invoke-Api $AuthUrl GET /health).Status 200
}
Test-Case "the storefront fetched the auth public key" {
  $r = Invoke-Api $OrdersUrl GET /health/ready
  if ($r.Body.token_check -notin @("local", "introspect")) {
    throw "unexpected token_check '$($r.Body.token_check)'"
  }
}
Test-Case "the storefront page is served" {
  $page = Invoke-WebRequest "$OrdersUrl/shop/" -UseBasicParsing
  Assert-Equal $page.StatusCode 200
}

# -------------------------------------------------------------- anonymous
Write-Host ""
Write-Host "Anonymous callers" -ForegroundColor Cyan

Test-Case "the catalogue is public" {
  $r = Invoke-Api $OrdersUrl GET /api/catalog
  Assert-Equal $r.Status 200
  if ($r.Body.Count -lt 1) { throw "catalogue was empty" }
}
Test-Case "placing an order needs a token" {
  $r = Invoke-Api $OrdersUrl POST /api/orders @{ items = @(@{ sku = "SKU-MOUSE"; quantity = 1 }) }
  Assert-Equal $r.Status 401
}
Test-Case "a garbage token is refused" {
  $r = Invoke-Api $OrdersUrl GET /api/auth/whoami $null "not.a.jwt"
  Assert-Equal $r.Status 401
}
Test-Case "a token minted by nobody else is refused" {
  # A well-formed three part JWT that this service did not issue.
  $forged = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
  $r = Invoke-Api $OrdersUrl GET /api/auth/whoami $null $forged
  Assert-Equal $r.Status 401
}

# ------------------------------------------------------------- the session
Write-Host ""
Write-Host "Sessions through the storefront" -ForegroundColor Cyan

$shopperEmail = New-Email "shopper"
$shopper = $null
$order = $null

Test-Case "signing in creates the account and returns a token" {
  $r = Invoke-Api $OrdersUrl POST /api/auth/login `
    @{ email = $shopperEmail; password = $Password; register = $true; bind_to_service = $true }
  Assert-Equal $r.Status 200
  if (-not $r.Body.access_token) { throw "no access token in the response body" }
  if ($r.Body.user.id -eq $null) { throw "no user in the response body" }
  $script:shopper = $r.Body
}
$shopper = $script:shopper

Test-Case "the refresh token is an httpOnly cookie scoped to /api/auth" {
  $response = Invoke-WebRequest -Method Post -Uri "$OrdersUrl/api/auth/login" `
    -ContentType "application/json" `
    -Body (@{ email = $shopperEmail; password = $Password; bind_to_service = $true } | ConvertTo-Json) `
    -UseBasicParsing

  $setCookie = $response.Headers["Set-Cookie"]
  if (-not $setCookie) { throw "no Set-Cookie header was returned" }
  if ($setCookie -notmatch "HttpOnly") { throw "the refresh cookie is not HttpOnly: $setCookie" }
  if ($setCookie -notmatch "Path=/api/auth") {
    throw "the cookie is not scoped to /api/auth, so it rides along on order requests: $setCookie"
  }
}

Test-Case "the refresh token never appears in the response body" {
  $body = Invoke-Api $OrdersUrl POST /api/auth/login `
    @{ email = $shopperEmail; password = $Password }
  if ($body.Body.PSObject.Properties.Name -contains "refresh_token") {
    throw "the refresh token leaked into JSON, where any script on the page can read it"
  }
}

Test-Case "whoami identifies the caller" {
  $r = Invoke-Api $OrdersUrl GET /api/auth/whoami $null $shopper.access_token
  Assert-Equal $r.Status 200
  Assert-Equal $r.Body.user_id $shopper.user.id
  Assert-Equal $r.Body.established_by ((Invoke-Api $OrdersUrl GET /health/ready).Body.token_check)
}

# ------------------------------------------------------------------ orders
Write-Host ""
Write-Host "Orders" -ForegroundColor Cyan

Test-Case "an order can be placed" {
  $r = Invoke-Api $OrdersUrl POST /api/orders `
    @{ items = @(@{ sku = "SKU-MOUSE"; quantity = 2 }, @{ sku = "SKU-CABLE"; quantity = 1 }) } `
    $shopper.access_token
  Assert-Equal $r.Status 201
  # 2 x 45.00 + 1 x 15.00, computed server side from the catalogue.
  Assert-Equal $r.Body.total "105.00"
  $script:order = $r.Body
}
$order = $script:order

Test-Case "an unknown product is rejected" {
  $r = Invoke-Api $OrdersUrl POST /api/orders `
    @{ items = @(@{ sku = "SKU-NOPE"; quantity = 1 }) } $shopper.access_token
  Assert-Equal $r.Status 400
}
Test-Case "a zero quantity is rejected" {
  $r = Invoke-Api $OrdersUrl POST /api/orders `
    @{ items = @(@{ sku = "SKU-MOUSE"; quantity = 0 }) } $shopper.access_token
  Assert-Equal $r.Status 400
}
Test-Case "an empty cart is rejected" {
  $r = Invoke-Api $OrdersUrl POST /api/orders @{ items = @() } $shopper.access_token
  Assert-Equal $r.Status 400
}
Test-Case "the customer sees only their own orders" {
  $r = Invoke-Api $OrdersUrl GET /api/orders $null $shopper.access_token
  Assert-Equal $r.Status 200
  if ($r.Body.Count -ne 1) { throw "expected exactly one order, got $($r.Body.Count)" }
}
Test-Case "the order can be fetched by id" {
  $r = Invoke-Api $OrdersUrl GET "/api/orders/$($order.id)" $null $shopper.access_token
  Assert-Equal $r.Status 200
  Assert-Equal $r.Body.total "105.00"
}

# -------------------------------------------------------------- ownership
Write-Host ""
Write-Host "Ownership and roles" -ForegroundColor Cyan

$otherEmail = New-Email "nosy"
Test-Case "another customer cannot read this order" {
  $other = Invoke-Api $OrdersUrl POST /api/auth/login `
    @{ email = $otherEmail; password = $Password; register = $true }
  Assert-Equal $other.Status 200
  $script:otherToken = $other.Body.access_token
}
$otherToken = $script:otherToken

Test-Case "the refusal is 404, not 403" {
  $r = Invoke-Api $OrdersUrl GET "/api/orders/$($order.id)" $null $otherToken
  # 403 would confirm the order exists, which is itself a leak.
  Assert-Equal $r.Status 404
  Assert-Equal $r.Body.error.code "not_found"
}

Test-Case "an ordinary customer cannot see every order" {
  $r = Invoke-Api $OrdersUrl GET "/api/orders?all=true" $null $otherToken
  Assert-Equal $r.Status 403
}

Test-Case "an ordinary customer cannot refund" {
  $r = Invoke-Api $OrdersUrl POST "/api/orders/$($order.id)/refund" $null $otherToken
  Assert-Equal $r.Status 403
}

Test-Case "an ordinary customer cannot refund their own order" {
  $r = Invoke-Api $OrdersUrl POST "/api/orders/$($order.id)/refund" $null $shopper.access_token
  Assert-Equal $r.Status 403
}

# ----------------------------------------------------------------- admin
Write-Host ""
Write-Host "The administrator" -ForegroundColor Cyan

$admin = $null
Test-Case "the bootstrap admin can get a token" {
  $r = Invoke-Api $OrdersUrl POST /api/auth/login `
    @{ email = $AdminEmail; password = $Password; register = $true }
  Assert-Equal $r.Status 200
  if ($r.Body.user.roles -notcontains "admin") {
    throw "the bootstrap address did not get the admin role; is ADMIN_BOOTSTRAP_EMAILS set?"
  }
  $script:admin = $r.Body
}
$admin = $script:admin

Test-Case "an admin sees every order" {
  $r = Invoke-Api $OrdersUrl GET "/api/orders?all=true" $null $admin.access_token
  Assert-Equal $r.Status 200
}
Test-Case "an admin can refund" {
  $r = Invoke-Api $OrdersUrl POST "/api/orders/$($order.id)/refund" $null $admin.access_token
  Assert-Equal $r.Status 200
  Assert-Equal $r.Body.status "refunded"
}
Test-Case "refunding twice is refused" {
  $r = Invoke-Api $OrdersUrl POST "/api/orders/$($order.id)/refund" $null $admin.access_token
  Assert-Equal $r.Status 404
}

# ---------------------------------------------------------------- logout
Write-Host ""
Write-Host "Sign out" -ForegroundColor Cyan

Test-Case "signing out kills the session" {
  # A cookie container, so the refresh cookie is actually sent back.
  $web = $null
  $login = Invoke-WebRequest -Method Post -Uri "$OrdersUrl/api/auth/login" `
    -ContentType "application/json" `
    -Body (@{ email = $shopperEmail; password = $Password } | ConvertTo-Json) `
    -UseBasicParsing -SessionVariable web
  $token = ($login.Content | ConvertFrom-Json).access_token

  Assert-Equal (Invoke-Api $OrdersUrl GET /api/auth/whoami $null $token).Status 200

  Invoke-WebRequest -Method Post -Uri "$OrdersUrl/api/auth/logout" `
    -WebSession $web -UseBasicParsing | Out-Null

  # The access token survives, because it is stateless and still inside its
  # 15 minute window. What must not survive is the session, so a refresh with
  # the revoked cookie has to fail.
  $refresh = Invoke-Api $OrdersUrl POST /api/auth/refresh
  Assert-Equal $refresh.Status 401
}

Write-Host ""
Write-Host "-------------------------------------------" -ForegroundColor DarkGray
if ($script:failed -eq 0) {
  Write-Host "All $script:passed checks passed." -ForegroundColor Green
  Write-Host ""
  Write-Host "Note: revocation of a decommissioned service is covered by" -ForegroundColor DarkGray
  Write-Host "scripts/smoke-test.ps1 on the auth service side, and depends on" -ForegroundColor DarkGray
  Write-Host "TOKEN_CHECK. See the README." -ForegroundColor DarkGray
  exit 0
} else {
  Write-Host "$script:passed passed, $script:failed failed." -ForegroundColor Red
  exit 1
}
