# Description
# The below script will any calls on a given domain. This module allows you to connect to your Netsapiens service provider. Initial pre-release. use at your own risk.

# License
# (c) 2021 Raymond Orsini - ray@oit.co All rights reserved. Free for personal or business use. Distribution or modification must include attribution.

# Setup
# Fill out the credential section below. Domain may be filled out in advance, or when calling the script.

# Usage
# Load the script. Then call `Disconnect-NSCalls'

# Credentials for connecting to switch
# Must be a user with Office Manager permissions or abvove
$fqdn = ""
$clientID = ""
$clientSecret = ""
$userName = ""
$password = ""

$domain = ""


#region Helper Functions

## Trap any errors
trap [Net.WebException] { continue; }
#Add Web Assembly for URL encoding
Add-Type -AssemblyName System.Web
# Authenticate against switch
Function Get-Token() {
    ## Helper function to get an access token. Required to perform calls against the API
    ## Scopes: Any
    $tokenURL = "https://" + $fqdn + "/ns-api/oauth2/token/?grant_type=password&client_id=" + $clientID + "&client_secret=" + $clientSecret + "&username=" + $userName + "&password=" + $password

    $response = Invoke-RestMethod $tokenURL
    $currentDate = Get-Date

    $Global:apiToken = New-Object -TypeName psobject
    $apiToken | Add-Member NoteProperty -Name accesstoken -Value $response.access_token
    $apiToken | Add-Member NoteProperty -Name expiration -Value $currentDate.AddSeconds(3600)
}

Function Invoke-NSRequest {
    ## Helper function to place API calls
    ## Scopes: Any
    param (
        [Parameter(Mandatory = $true)][Hashtable]$load,
        [Parameter(Mandatory = $false)][String]$type
    )
    # Check if payload submitted
    if (!$load) {
        Write-Host -ForegroundColor Red "Invalid or missing payload. Killing application"
        exit
    }
    # NS token expires in 1 hour. Check if token is still valid. If not, request a new one
    if ((!$apitoken) -or ((Get-Date) -lt $apitoken.expiration)) {
        Get-Token
    }

    # Check if request is POST or GET. Set GET by default
    if (!$type) { $type = "GET" }

    # Add format descriptor in case it's missing
    if (!$load.format) { $load.add('format', 'json') }

    # Set headers
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", 'Bearer ' + $apitoken.accesstoken)

    # Set request URL
    $requrl = "https://" + $fqdn + "/ns-api/"

    $response = Invoke-RestMethod $requrl -Headers $headers -Method $type -Body $load
    return $response
}
#endregion

## Kill Domain Calls
Function Disconnect-NSCalls {
    ## Kills all calls on a given domain. Normally used for fraud events
    ## Scopes: Super User
    param (
        [Parameter(Mandatory = $true)][String]$domain
    )
    
    $payload = @{
        object = 'call'
        action = 'read'
        domain = $domain
    }    
    Try {
        $calls = Invoke-NSRequest $payload
    }
    Catch {
        $res = "No data returned"
        return $res
    }

    foreach($call in $calls){
        $payload = @{
            object = 'call'
            action = 'disconnect'
            callid = $call.orig_callid
            uid = $userName
        
        }
        Try {
            $res = NS-Call $payload
            Write-Output $call.orig_callid "terminated"
        }
        Catch {
            $res = "No data returned"
            return $res
        }
    }
}