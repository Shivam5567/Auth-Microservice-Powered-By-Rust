# Log in as the bootstrap admin and print a token for the admin panel.
$pw = 'correct horse battery staple'
$token = (Invoke-RestMethod -Method Post 'http://localhost:8081/api/v1/auth/login' 
  -ContentType 'application/json' 
  -Body (@{ email = 'boss@example.com'; password = $pw } | ConvertTo-Json)).access_token
Write-Host $token
