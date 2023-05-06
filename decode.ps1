$string = "YUhSMGNITTZMeTkzZDNjdWJXVmthV0ZtYVhKbExtTnZiUzltYVd4bEx6UjNiRFUwTkRFM2N6bGxZWFZxTlM5UWQxOXBjMTlCVWxSSVZWSXVlbWx3TDJacGJHVT0="
$passphrase = "ARTHUR"

# Decrypt decoded string using passphrase
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($string))

# Decode base64 string
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($decoded))

# Print decoded string
Write-Host $decoded