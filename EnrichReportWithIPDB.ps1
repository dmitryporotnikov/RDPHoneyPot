#Put your own API key and paths here
$inputCsvPath = "C:\temp\ConnectionLogs.csv"
$outputCsvPath = "C:\temp\ConnectionLogsEnriched.csv"
$apiKey = ""  # Replace with your actual AbuseIPDB API key

$rows = Import-Csv $inputCsvPath
$outputData = @()
foreach ($row in $rows) {

    $ipAddress = $row.IPAddress
    $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$($ipAddress)&maxAgeInDays=90&verbose"
    $headers = @{
        "Key" = $apiKey
        "Accept" = "application/json"
    }

    $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

    $data = $response.data
    $newFields = @{
        "isPublic" = $data.isPublic
        "ipVersion" = $data.ipVersion
        "isWhitelisted" = $data.isWhitelisted
        "abuseConfidenceScore" = $data.abuseConfidenceScore
        "countryCode" = $data.countryCode
        "countryName" = $data.countryName
        "usageType" = $data.usageType
        "isp" = $data.isp
        "domain" = $data.domain
        "hostnames" = if ($data.hostnames) { $data.hostnames -join "," } else { "" }
        "isTor" = $data.isTor
        "totalReports" = $data.totalReports
        "numDistinctUsers" = $data.numDistinctUsers
        "lastReportedAt" = $data.lastReportedAt
    }

    $outputRow = $row.PSObject.Copy()
    foreach ($key in $newFields.Keys) {
        $outputRow | Add-Member -MemberType NoteProperty -Name $key -Value $newFields[$key]
    }

    $outputData += $outputRow
}
$outputData | Export-Csv $outputCsvPath -NoTypeInformation
