<#
.SYNOPSIS
  Exercises the running auth service end to end and reports pass or fail.

.DESCRIPTION
  Walks the whole surface against a live instance: the auth flow, the token
  theft case, the admin registry, and the fact that removing a downstream
  service really does revoke its tokens.

  Exits non-zero if anything fails, so it can be used as a gate.

.EXAMPLE
  pwsh ./scripts/smoke-test.ps1
  pwsh ./scripts/smoke-test.ps1 -BaseUrl http://localhost:8080
#>
[CmdletBinding()]
param(
  [string] $BaseUrl = "http://localhost:8081",
  [string] $AdminEmail = "boss@example.com",
  [string] $Password = "correct horse battery staple"
)

$ErrorActionPreference = "Stop"
$script:passed = 0
$script:failed = 0

function Test-Case {
  param([string] $Name, [scriptblock] $Body)

  try {
    # Must invoke the block, not pipe it: piping a scriptblock to Out-Null
    # discards it without running it, and every case would report PASS.
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
  if ($Actual -ne $Expected) {
    throw "expected '$Expected' but got '$Actual'. $Because"
  }
}

function Assert-Status {
  param($Response, [int] $Expected)
  Assert-Equal $Response.Status $Expected "status code"
}

function New-Email {
  param([string] $Prefix)
  "$Prefix-$([guid]::NewGuid().ToString('N').Substring(0, 8))@example.com"
}

function Invoke-Api {
  param(
    [string] $Method, [string] $Path,
    $Body, [string] $Token
  )
  $params = @{
    Uri         = "$BaseUrl$Path"
    Method      = $Method
    ErrorAction = "Stop"
  }
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
    # Windows PowerShell 5.1 hands the body over in ErrorDetails, while the
    # response object carries only the status. Read both.
    $status = 0
    if ($null -ne $_.Exception.Response) {
      $status = [int] $_.Exception.Response.StatusCode
    }
    $text = $_.ErrorDetails.Message
    if ([string]::IsNullOrWhiteSpace($text) -and $null -ne $_.Exception.Response) {
      $text = $_.Exception.Response.Content
    }
  }

  $parsed = $null
  if (-not [string]::IsNullOrWhiteSpace($text)) {
    try { $parsed = $text | ConvertFrom-Json } catch { $parsed = $null }
  }

  return [pscustomobject]@{ Status = $status; Body = $parsed; Raw = $text }
}

Write-Host ""
Write-Host "Auth service smoke test against $BaseUrl" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------- health
Write-Host "Health" -ForegroundColor Cyan
Test-Case "liveness responds" {
  Assert-Equal (Invoke-Api GET /health).Status 200
}
Test-Case "readiness reports the database" {
  $r = Invoke-Api GET /health/ready
  Assert-Equal $r.Status 200
  Assert-Equal $r.Body.database "connected"
}

# ------------------------------------------------------------ admin token
Write-Host ""
Write-Host "Admin access" -ForegroundColor Cyan

# The bootstrap admin may not be registered yet on a fresh database.
$admin = Invoke-Api POST /api/v1/auth/login @{ email = $AdminEmail; password = $Password }
if ($admin.Status -ne 200) {
  Invoke-Api POST /api/v1/auth/register @{ email = $AdminEmail; password = $Password } | Out-Null
  $admin = Invoke-Api POST /api/v1/auth/login @{ email = $AdminEmail; password = $Password }
}

$adminToken = $null
Test-Case "an admin token is obtainable" {
  Assert-Equal $admin.Status 200 "is the address in ADMIN_BOOTSTRAP_EMAILS?"
  $script:adminToken = $admin.Body.access_token
  $script:adminToken
}
$adminToken = $script:adminToken

# The auth routes are throttled per IP and this script is one client, so against
# a production limit it would produce a wall of 429s that says nothing about
# the service. Checked before the missing-token branch, since a 429 also means
# no token arrived.
if ($admin.Status -eq 429) {
  Write-Host ""
  Write-Host "The service is rate limiting this script." -ForegroundColor Yellow
  Write-Host "Start it with the test override, which raises the limit:" -ForegroundColor Yellow
  Write-Host "  docker compose -f docker-compose.yml -f docker-compose.test.yml up --build -d" -ForegroundColor Yellow
  exit 3
}

if (-not $adminToken) {
  Write-Host ""
  Write-Host "Cannot continue without an admin token." -ForegroundColor Red
  Write-Host "Set ADMIN_BOOTSTRAP_EMAILS=$AdminEmail and restart the stack." -ForegroundColor Yellow
  exit 2
}

Test-Case "the token really carries the admin role" {
  $me = Invoke-Api GET /api/v1/auth/me $null $adminToken
  Assert-Equal $me.Status 200
  if ($me.Body.roles -notcontains "admin") {
    throw "token lacks the admin role; got $($me.Body.roles -join ',')"
  }
}

# ------------------------------------------------------------- auth flow
Write-Host ""
Write-Host "Auth flow" -ForegroundColor Cyan

$user = New-Email "smoke"
$userToken = $null

Test-Case "register returns the profile" {
  $r = Invoke-Api POST /api/v1/auth/register @{ email = $user; password = $Password }
  Assert-Status $r 201
  Assert-Equal $r.Body.email $user
  Assert-Equal ($r.Body.roles -join ",") "user"
}

Test-Case "a duplicate registration is refused" {
  $r = Invoke-Api POST /api/v1/auth/register @{ email = $user; password = $Password }
  Assert-Status $r 409
}

Test-Case "an email differing only in case is the same account" {
  $r = Invoke-Api POST /api/v1/auth/register @{ email = $user.ToUpper(); password = $Password }
  Assert-Status $r 409
}

Test-Case "login returns a usable pair" {
  $r = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = $Password }
  Assert-Status $r 200
  Assert-Equal $r.Body.token_type "Bearer"
  Assert-Equal ($r.Body.access_token -split "\.").Count 3 "should be a three part JWT"
  $script:userToken = $r.Body.access_token
  $script:userRefresh = $r.Body.refresh_token
}
$userToken = $script:userToken
$userRefresh = $script:userRefresh

Test-Case "a wrong password is rejected" {
  $r = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = "not it" }
  Assert-Status $r 401
}

Test-Case "an unknown address is refused identically" {
  $r = Invoke-Api POST /api/v1/auth/login @{ email = (New-Email "ghost"); password = "not it" }
  Assert-Status $r 401
  Assert-Equal $r.Body.error.message "invalid email or password" "must not leak whether the account exists"
}

Test-Case "me identifies the caller" {
  $r = Invoke-Api GET /api/v1/auth/me $null $userToken
  Assert-Status $r 200
  Assert-Equal $r.Body.email $user
}

Test-Case "a missing token is refused" {
  Assert-Status (Invoke-Api GET /api/v1/auth/me) 401
}

Test-Case "a forged token is refused" {
  Assert-Status (Invoke-Api GET /api/v1/auth/me $null "not.a.real.jwt") 401
}

Test-Case "an ordinary user cannot reach the admin API" {
  Assert-Status (Invoke-Api GET /api/v1/admin/services $null $userToken) 403
}

# ------------------------------------------------------------- validation
Write-Host ""
Write-Host "Input validation" -ForegroundColor Cyan

Test-Case "a malformed email is rejected" {
  $r = Invoke-Api POST /api/v1/auth/register @{ email = "not-an-email"; password = $Password }
  Assert-Status $r 400
  Assert-Equal $r.Body.error.code "validation_failed"
}

Test-Case "a short password is rejected" {
  $r = Invoke-Api POST /api/v1/auth/register @{ email = (New-Email "short"); password = "abc" }
  Assert-Status $r 400
}

Test-Case "the error names the offending field" {
  $r = Invoke-Api POST /api/v1/auth/register @{ email = "bad"; password = "abc" }
  if ($r.Body.error.message -notmatch "email") { throw "should mention email" }
  if ($r.Body.error.message -notmatch "password") { throw "should mention password" }
}

Test-Case "an unknown route returns the shared envelope" {
  $r = Invoke-Api GET /api/v1/definitely-not-here
  Assert-Status $r 404
  Assert-Equal $r.Body.error.code "not_found"
}

Test-Case "every response carries a request id" {
  $response = Invoke-WebRequest "$BaseUrl/health" -UseBasicParsing
  if (-not $response.Headers.ContainsKey("x-request-id")) { throw "no x-request-id header" }
}

# ---------------------------------------------------------------- refresh
Write-Host ""
Write-Host "Token rotation" -ForegroundColor Cyan

$rotated = $null
Test-Case "a refresh token can be exchanged" {
  $r = Invoke-Api POST /api/v1/auth/refresh @{ refresh_token = $userRefresh }
  Assert-Status $r 200
  if ($r.Body.refresh_token -eq $userRefresh) { throw "token was not rotated" }
  $script:rotated = $r.Body.refresh_token
  $script:rotatedAccess = $r.Body.access_token
}
$rotated = $script:rotated
$rotatedAccess = $script:rotatedAccess

Test-Case "the rotated access token works" {
  Assert-Status (Invoke-Api GET /api/v1/auth/me $null $rotatedAccess) 200
}

Test-Case "the spent token cannot be reused" {
  Assert-Status (Invoke-Api POST /api/v1/auth/refresh @{ refresh_token = $userRefresh }) 401
}

Test-Case "the replay burned the whole family" {
  # The attacker's token dies too, which is the point of reuse detection.
  Assert-Status (Invoke-Api POST /api/v1/auth/refresh @{ refresh_token = $rotated }) 401
}

# ------------------------------------------------------- admin registry
Write-Host ""
Write-Host "Downstream service registry" -ForegroundColor Cyan

$serviceId = [guid]::NewGuid().ToString("N").Substring(0, 8)
# The canonical name the service will end up with, after normalisation.
$service = "smoke-$serviceId-api"
$boundAccess = $null
$boundRefresh = $null

Test-Case "a service can be registered" {
  # Deliberately messy input, to prove the name gets normalised on the way in
  # and that the panel's canonical form is what comes back.
  $r = Invoke-Api POST /api/v1/admin/services `
    @{ name = "  Smoke $serviceId API "; description = "created by the smoke test"; scopes = @("read") } $adminToken
  Assert-Status $r 201
  Assert-Equal $r.Body.name $service "the name should be normalised"
  Assert-Equal $r.Body.status "active"
  Assert-Equal $r.Body.token_version 0
  Assert-Equal ($r.Body.scopes -join ",") "read"
}

Test-Case "the same service cannot be registered twice" {
  $r = Invoke-Api POST /api/v1/admin/services @{ name = $service } $adminToken
  Assert-Status $r 409
}

Test-Case "a differently spelled duplicate is still the same service" {
  # Braces required: PowerShell would otherwise read $serviceId_api as a
  # variable name and send the literal "smoke_".
  $r = Invoke-Api POST /api/v1/admin/services @{ name = "smoke_${serviceId}_api" } $adminToken
  Assert-Status $r 409
}

Test-Case "the service appears in the list" {
  $r = Invoke-Api GET "/api/v1/admin/services?search=$service" $null $adminToken
  Assert-Status $r 200
  Assert-Equal $r.Body.services.Count 1
}

Test-Case "an unknown status filter is rejected" {
  Assert-Status (Invoke-Api GET "/api/v1/admin/services?status=actve" $null $adminToken) 400
}

Test-Case "logging in for the service binds the token to it" {
  $r = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = $Password; service = $service }
  Assert-Status $r 200
  $script:boundAccess = $r.Body.access_token
  $script:boundRefresh = $r.Body.refresh_token
  Assert-Status (Invoke-Api GET /api/v1/auth/me $null $r.Body.access_token) 200
}
$boundAccess = $script:boundAccess
$boundRefresh = $script:boundRefresh

Test-Case "logging in for an unknown service is refused" {
  $r = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = $Password; service = "never-registered" }
  Assert-Status $r 400
}

# ---------------------------------------------------------------- removal
Write-Host ""
Write-Host "Removal revokes live tokens" -ForegroundColor Cyan

Test-Case "removing the service bumps its version" {
  $r = Invoke-Api DELETE "/api/v1/admin/services/$service" $null $adminToken
  Assert-Status $r 200
  Assert-Equal $r.Body.status "disabled"
  Assert-Equal $r.Body.token_version 1
}

Test-Case "the already issued token stops working immediately" {
  $r = Invoke-Api GET /api/v1/auth/me $null $boundAccess
  Assert-Status $r 403 "this is the whole point of the feature"
}

Test-Case "the session cannot be refreshed either" {
  Assert-Status (Invoke-Api POST /api/v1/auth/refresh @{ refresh_token = $boundRefresh }) 403
}

Test-Case "removing again is harmless" {
  $r = Invoke-Api DELETE "/api/v1/admin/services/$service" $null $adminToken
  Assert-Status $r 200
  Assert-Equal $r.Body.token_version 1 "the version should not move again"
}

Test-Case "an unbound token is unaffected" {
  Assert-Status (Invoke-Api GET /api/v1/auth/me $null $rotatedAccess) 200
}

Test-Case "the service can be restored" {
  $r = Invoke-Api POST "/api/v1/admin/services/$service/restore" $null $adminToken
  Assert-Status $r 200
  Assert-Equal $r.Body.status "active"
  Assert-Equal $r.Body.token_version 2 "restoring must invalidate older tokens"
}

Test-Case "a pre removal token does not come back to life" {
  Assert-Status (Invoke-Api GET /api/v1/auth/me $null $boundAccess) 401
}

Test-Case "a fresh login works again" {
  $r = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = $Password; service = $service }
  Assert-Status $r 200
  Assert-Status (Invoke-Api GET /api/v1/auth/me $null $r.Body.access_token) 200
}

# ----------------------------------------------------------------- logout
Write-Host ""
Write-Host "Sign out" -ForegroundColor Cyan

Test-Case "logging out one session leaves the other alone" {
  $a = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = $Password }
  $b = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = $Password }

  $r = Invoke-Api POST /api/v1/auth/logout @{ refresh_token = $a.Body.refresh_token }
  Assert-Status $r 204
  Assert-Status (Invoke-Api POST /api/v1/auth/refresh @{ refresh_token = $a.Body.refresh_token }) 401
  Assert-Status (Invoke-Api POST /api/v1/auth/refresh @{ refresh_token = $b.Body.refresh_token }) 200
}

Test-Case "logging out everywhere also kills live access tokens" {
  $a = Invoke-Api POST /api/v1/auth/login @{ email = $user; password = $Password }
  $r = Invoke-Api POST /api/v1/auth/logout @{ refresh_token = $a.Body.refresh_token; all_devices = $true }
  Assert-Status $r 204
  Assert-Status (Invoke-Api GET /api/v1/auth/me $null $a.Body.access_token) 401
}

Test-Case "signing out an unknown token is not an error" {
  Assert-Status (Invoke-Api POST /api/v1/auth/logout @{ refresh_token = "never-existed" }) 204
}

# ------------------------------------------------------------------ panel
Write-Host ""
Write-Host "Admin panel" -ForegroundColor Cyan

Test-Case "the panel page is served" {
  $response = Invoke-WebRequest "$BaseUrl/admin/" -UseBasicParsing
  Assert-Equal $response.StatusCode 200
  if (-not $response.Content.Contains('data-panel="admin-services"')) { throw "not the panel page" }
}

Test-Case "the panel carries a content security policy" {
  $response = Invoke-WebRequest "$BaseUrl/admin/" -UseBasicParsing
  if (-not $response.Headers.ContainsKey("Content-Security-Policy")) { throw "no CSP header" }
}

Test-Case "the activity log recorded the changes" {
  $r = Invoke-Api GET "/api/v1/admin/services/events" $null $adminToken
  Assert-Status $r 200
  if (-not ($r.Body | Where-Object { $_.service -eq $service -and $_.action -eq "removed" })) {
    throw "the removal was not recorded"
  }
}

# ----------------------------------------------------------------- report
Write-Host ""
Write-Host "-------------------------------------------" -ForegroundColor DarkGray
if ($script:failed -eq 0) {
  Write-Host "All $script:passed checks passed." -ForegroundColor Green
  exit 0
} else {
  Write-Host "$script:passed passed, $script:failed failed." -ForegroundColor Red
  exit 1
}
