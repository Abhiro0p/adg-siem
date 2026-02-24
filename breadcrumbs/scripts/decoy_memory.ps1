$secrets = @(
  "DOMAIN\\svc_backup:Summer2026!",
  "DOMAIN\\svc_ci:Winter2026!",
  "KRBTGT:DecoyTicket-123456"
)
while ($true) { Start-Sleep -Seconds 60 }
