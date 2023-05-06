$client_id = 'DE-103101'
$client_secret = '2a5b75f0-f02f-41d8-9835-55ffd08f9f52'
$api_user = 'kling.mobil@icloud.com'
$api_password = 'Kiranna01!!!'
$body = @{grant_type = 'password'
    client_id        = $client_id
    client_secret    = $client_secret
    username         = $api_user
    password         = $api_password
}
$response = Invoke-WebRequest -Uri 'https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token' -Method 'POST' -Body $body
$access_token = (ConvertFrom-Json $([String]::new($response.Content))).access_token


# print access token
$access_token


# get list of your instances
$headers = @{}
$headers.Add("Authorization", "Bearer $access_token")
$headers.Add("x-request-id", "51A87ECD-754E-4104-9C54-D01AD0F83406")
Invoke-WebRequest -Uri 'https://api.contabo.com/v1/compute/instances' -Method 'GET' -Headers $headers


