$uri = 'http://127.0.0.1:5000/scan'
$payload = [pscustomobject]@{ domain = 'unair.ac.id'; quick = 1 }
$json = $payload | ConvertTo-Json -Depth 5
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromSeconds(15)
$content = New-Object System.Net.Http.StringContent($json, [System.Text.Encoding]::UTF8, 'application/json')
$response = $client.PostAsync($uri, $content).GetAwaiter().GetResult()
$body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
$body
