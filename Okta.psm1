$ExecutionContext.SessionState.Module.OnRemove = {
    Remove-Module Okta_org
}

function _oktaThrowError()
{
    param
    (
        [parameter(Mandatory=$true)][String]$text
    )

    try
    {
        $OktaSays = ConvertFrom-Json -InputObject $text
    }
    catch
    {
        throw $text
    }
    <# Can't decide what to throw here... #>
    <# Highly subject to change... #>
    if ($OktaSays.errorCauses[0].errorSummary)
    {
        $formatError = New-Object System.FormatException -ArgumentList ($OktaSays.errorCode + " ; " + $OktaSays.errorCauses[0].errorSummary)
    } else {
        $formatError = New-Object System.FormatException -ArgumentList ($OktaSays.errorCode + " ; " + $OktaSays.errorSummary)
    }
    #@@@ too bad this doesn't actually work    
    $formatError.HelpLink = $text
    $formatError.Source = $Error[0].Exception
    throw $formatError
}

function oktaNewPassword
{
    param
    (
        [Int32]$Length = 15,
        [Int32]$MustIncludeSets = 3
    )

    $CharacterSets = @("ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwzyz","0123456789","!$-#")

    $Random = New-Object Random

    $Password = ""
    $IncludedSets = ""
    $IsNotComplex = $true
    while ($IsNotComplex -or $Password.Length -lt $Length)
    {
        $Set = $Random.Next(0, 4)
        if (!($IsNotComplex -and $IncludedSets -match "$Set" -And $Password.Length -lt ($Length - $IncludedSets.Length)))
        {
            if ($IncludedSets -notmatch "$Set")
            {
                $IncludedSets = "$IncludedSets$Set"
            }
            if ($IncludedSets.Length -ge $MustIncludeSets)
            {
                $IsNotcomplex = $false
            }

            $Password = "$Password$($CharacterSets[$Set].SubString($Random.Next(0, $CharacterSets[$Set].Length), 1))"
        }
    }
    return $Password
}

function oktaRandLower
{
    param
    (
        [Int32]$Length = 18,
        [Int32]$MustIncludeSets = 3
    )

    $CharacterSets = @("abcdefghijklmnopqrstuvwzyz","abcdefghijklmnopqrstuvwzyz","abcdefghijklmnopqrstuvwzyz","abcdefghijklmnopqrstuvwzyz")

    $Random = New-Object Random

    $Password = ""
    $IncludedSets = ""
    $IsNotComplex = $true
    while ($IsNotComplex -or $Password.Length -lt $Length)
    {
        $Set = $Random.Next(0, 4)
        if (!($IsNotComplex -and $IncludedSets -match "$Set" -And $Password.Length -lt ($Length - $IncludedSets.Length)))
        {
            if ($IncludedSets -notmatch "$Set")
            {
                $IncludedSets = "$IncludedSets$Set"
            }
            if ($IncludedSets.Length -ge $MustIncludeSets)
            {
                $IsNotcomplex = $false
            }

            $Password = "$Password$($CharacterSets[$Set].SubString($Random.Next(0, $CharacterSets[$Set].Length), 1))"
        }
    }
    return $Password
}

function oktaExternalIdtoGUID()
{
    param
    (
        [parameter(Mandatory=$true)][String]$externalId
    )
    
    $bytes = [System.Convert]::FromBase64String($externalId)
    $guid = New-Object -TypeName System.Guid -ArgumentList(,$bytes)
    return $guid
}

function oktaConverttoSecureString()
{
    param
    (
        [string]$insecureString
    )
    if ($insecureString)
    {
        $secureString = (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -AsPlainText -Force -String $insecureString))
    } else {
        $secureString = (ConvertFrom-SecureString -SecureString (Read-Host -AsSecureString -Prompt "PlainText Secret Key"))
    }
    return $secureString
}

function oktaProcessHeaderLink()
{
    param
    (
        [Parameter(Mandatory=$true)]$linkHeader
    )
    #may need to tweak to support windows and mac since they seem to have a different behavior here.
    if ($linkHeader -is [System.String[]])
    {
        $links = $linkHeader
    } elseif ($linkHeader -is [System.String])
    {
        $links = $linkHeader.Split(",")
    }

    Write-Verbose("we got header links! " + $links.Count + " of them actually")
    [HashTable]$olinks = @{}
    
    foreach ($link in $links)
    {
        #Yes I know it is a regex, but sometimes they work better
        if ($link.Trim() -match '^<(https://.+)>; rel="(\w+)"$')
        {
            $olinks.add($Matches[2].Trim(), $Matches[1].Trim())
        }
    }
    return $olinks
}

function oktaMakeUserAgent()
{
    if ($Global:defaultUserAgent)
    {
        return $Global:defaultUserAgent
    }

    if ($PSVersionTable.Contains("OS"))
    {
        $psOs = $PSVersionTable["OS"].ToString()
    } else {
        $psOs = "UnknownOS"
    }

    if ($PSVersionTable.Contains("Platform"))
    {
        $psPlatform = $PSVersionTable["Platform"].ToString()
    } else {
        $psPlatform = "UnknownPlatform"
    }

    if ($PSVersionTable.Contains("PSVersion"))
    {
        $psVer = $PSVersionTable["PSVersion"].ToString()
    } else {
        $psVer = "UnknownPsVer"
    }

    $module = Get-Module -Name Okta
    $modVer = $module.Version.ToString()

    $userAgent = "Okta-PSModule/" + $modVer + " (" + $psVer + ")" + " (" + $psPlatform + ")"+ " (" + $psOs + ")"
    Write-Verbose("Just Made this UserAgent: " + $userAgent)
    $Global:defaultUserAgent = $userAgent
    return $userAgent
}

function oktaBuildURIQuery()
{
    param
    (
        [parameter(Mandatory=$true)][UriBuilder]$uri,
        [parameter(Mandatory=$true)][Hashtable]$addParams
    )

    foreach ($key in $addParams.Keys)
    {
        $addParam = $key + "=" + $addParams[$key]
        if ($uri.Query.Length -eq 0)
        {
            $uri.Query = $addParam
        } else {
            $uri.Query = $uri.Query.Substring(1) + "&" + $addParam
        }
    }
    return $uri
}

function oktaBuildURI()
{
    param
    (
        [parameter(Mandatory=$true)][string]$resource,
        [parameter(Mandatory=$true)][Hashtable]$params
    )
    Write-Verbose("Start: " + $resource)
    $uri = [System.UriBuilder]::new("https", "hostplaceholder", 443, $resource)

    foreach ($key in $params.Keys)
    {
        $param = $key + "=" + $params[$key]
        if ($uri.Query.Length -eq 0)
        {
            $uri.Query = $param
        } else {
            $uri.Query = $uri.Query.Substring(1) + "&" + $param
        }
    }
    $newResource = ($uri.Path + $uri.Query)
    Write-Verbose("Before: " + $newResource)
    $newResource = [System.Web.HttpUtility]::UrlPathEncode($newResource)
    Write-Verbose(" After: " + $newResource)
    
    return $newResource
}

function _testOrg()
{
    param
    (
        [parameter(Mandatory=$true)][String]$org
    )
    if ($oktaOrgs[$org])
    {
        return $true
    } else {
        $estring = "The Org:" + $org + " is not defined in the Okta_org.ps1 file"
        throw $estring
    }
}

function OktaUserfromJson()
{
    param
    (
        $user
    )

    $dateFields = ('created','activated','statusChanged','lastLogin','lastUpdated','passwordChanged')

    foreach ($df in $dateFields)
    {
        if ($user.$df)
        {
            $user.$df = Get-Date $user.$df
        } else {
            $user.$df = $null
        }
    }
    return $user
}

function OktaAppfromJson()
{
    param
    (
        $app
    )

    $dateFields = ('created','lastUpdated')

    foreach ($df in $dateFields)
    {
        if ($app.$df)
        {
            $app.$df = Get-Date $app.$df
        } else {
            $app.$df = $null
        }
    }
    return $app
}

function OktaAppUserfromJson()
{
    param
    (
        $appUser,
        [parameter(Mandatory=$false)][switch]$skinny
    )

    if ($skinny)
    {
        $dateFields = ('created','lastUpdated','statusChanged','passwordChanged')
    } else {
        $dateFields = ('created','lastUpdated','statusChanged','passwordChanged','lastSync')
    }

    foreach ($df in $dateFields)
    {
        if ($appUser.$df)
        {
            $appUser.$df = Get-Date $appUser.$df
        } else {
            $appUser.$df = $null
        }
    }
    return $appUser
}

function OktaRolefromJson()
{
    param
    (
        $role
    )

    $dateFields = ('created','lastUpdated')

    foreach ($df in $dateFields)
    {
        if ($role[$df])
        {
            $role[$df] = Get-Date $role.$df
        } else {
            $role[$df] = $null
        }
    }
    return $role
}

$okta_epoch =  New-Object System.DateTime (1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
function _oktaRateLimitTimeRemaining()
{
    param
    (
        [long]$seconds
    )

    $reset = $okta_epoch.AddSeconds($seconds)
    $now = Get-Date
    $timeToReset = New-TimeSpan -Start ($now.ToUniversalTime()) -End $reset
    return $timeToReset.TotalSeconds
}

function _oktaRateLimitCheck()
{
    #this needs some work...
    [double]$warn = .50
    [double]$throttle = .20
    #how many other calls per second should we assume are there for backoff calculations?
    [int]$cps = 16

    $remain = [int][string]$rateLimt.Remaining
    $limit = [int][string]$rateLimt.Limit
    $reset = [long][string]$rateLimt.Reset

    $used = ($remain / $limit)
    $usedpct = $used.ToString("P")
    $limit_note = "You have $remain out of $limit aka: $usedpct left in the tank"

    if ($remain -eq 0)
    {
        Write-Verbose("remain is 0")
        $remain = 1
    }

    if ($used -lt $warn)
    {
        $reset = _oktaRateLimitTimeRemaining -seconds $reset
        $limit_note = "You have $remain out of $limit aka: $used in the next $reset seconds"
        Write-Warning($limit_note)

        if ($used -lt $throttle)
        {
            if ($reset -lt 10) { $reset = 10 }
            # how aggressive should we sleep?  same logic for now.
            if ( ($reset * $cps) -gt ($remain) )
            {
                $aggr = "hard"
                $sleepTime = (( ($reset * $cps) / $remain) * 1000)
            } else {
                $aggr = "soft"
                $sleepTime = (( ($reset * $cps) / $remain) * 10)
            }

            if ($sleepTime -gt ($reset * 1000) )
            {
                Write-Verbose ("Backoff on the sleep man!")
                $sleepTime = (($reset + 10) * 1000)
            }

            Write-Warning("Throttling " + $aggr + " for: " + $sleepTime + " milliseconds" )
            Start-Sleep -Milliseconds $sleepTime
        }

    } else {
        Write-Verbose($limit_note)
    }
}

$resHeaders = @(
    "X-Okta-Request-Id",
    "X-Rate-Limit-Limit",
    "X-Rate-Limit-Remaining",
    "X-Rate-Limit-Reset",
    "Link",
    "Content-Length",
    "Content-Type",
    "Date"
)

function _oktaMakeCall()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateSet("Get", "Head", "Post", "Put", "Delete")][String]$method,
        [parameter(Mandatory=$true)][String]$uri,
        [parameter(Mandatory=$true)][hashtable]$headers,
        [parameter(Mandatory=$false)][Object]$body = @{},
        [parameter(Mandatory=$false)][String]$userAgent
    )

    $contentType = "application/json"

    if (!$userAgent)
    {
        $userAgent = oktaMakeUserAgent
    }

    try
    {
        if (!$Global:myWebSession)
        {
            Write-Verbose("Creating myWebSession first")
            if ( ($method -eq "Post") -or ($method -eq "Put") )
            {
                $postData = ConvertTo-Json $body -Depth 10
                Write-Verbose($postData)
                $request2 = Invoke-WebRequest -Uri $uri -Method $method -UserAgent $userAgent -Headers $headers `
                            -ContentType $contentType -Verbose:$oktaVerbose -Body $postData -ErrorVariable evar -SessionVariable Global:myWebSession
            } else {
                $request2 = Invoke-WebRequest -Uri $uri -Method $method -UserAgent $userAgent -Headers $headers `
                            -ContentType $contentType -Verbose:$oktaVerbose -ErrorVariable evar -SessionVariable Global:myWebSession
            }
        } else {
            if ( ($method -eq "Post") -or ($method -eq "Put") )
            {
                $postData = ConvertTo-Json $body -Depth 10
                Write-Verbose($postData)
                $request2 = Invoke-WebRequest -Uri $uri -Method $method -UserAgent $userAgent -Headers $headers `
                            -ContentType $contentType -Verbose:$oktaVerbose -Body $postData -ErrorVariable evar -WebSession $Global:myWebSession
            } else {
                $request2 = Invoke-WebRequest -Uri $uri -Method $method -UserAgent $userAgent -Headers $headers `
                            -ContentType $contentType -Verbose:$oktaVerbose -ErrorVariable evar -WebSession $Global:myWebSession  
            }
        }

        <# Verbose Request header readout #>
        foreach ($h in $headers.Keys)
        {
            if ($h -eq 'Authorization')
            {
                Write-Verbose("Req-Hdr: " + $h + " -> SSWS xXxXxXxxXxxXxXxXxxXx")
            } else {
                Write-Verbose("Req-Hdr: " + $h + " -> " + $headers[$h])
            }
        }
        Write-Verbose("Req-Hdr: " + "Content-Type" + " -> " + $contentType)
        Write-Verbose("Req-Hdr: " + "User-Agent" + " -> " + $userAgent)
    }
    catch [System.Net.WebException], [Microsoft.PowerShell.Commands.HttpResponseException]
    {
        
        $code = $_.Exception.Response.StatusCode
        
        if ( $_.Exception.Response.Headers.Contains('X-Okta-Requst-Id') )
        {
            $reqId = $_.Exception.Response.Headers.GetValues('X-Okta-Requst-Id')
            Write-Warning("Okta Request ID: " + $reqId[0])
        }
        
        if ($_.ErrorDetails.Message)
        {
            try
            {
                $oktaException = ConvertFrom-Json -InputObject $_.ErrorDetails.Message
            }
            catch {
                $oktaException = $false
            }
            if ($oktaException)
            {
                $oktaMessage = "`nerrorCode: " + $oktaException.errorCode
                $oktaMessage += "; errorSummary: " + $oktaException.errorSummary
                $oktaMessage += "; errorId: " + $oktaException.errorId
                $oktaMessage += "`n`tcauses:`n"
                foreach ($cause in $oktaException.errorCauses)
                {
                    $oktaMessage += "`t`t" + $cause.errorSummary + "`n"
                }
                Write-Error($oktaMessage)
            } else {
                Write-Error($_.ErrorDetails.Message.ToString())
            }
        }

        switch ($code)
        {
            "429"
            {
                Write-Warning("You hit the rate limit!")
            }
            "BadRequest"
            {
                Write-Warning("Your request was bad!")
                #Write-Warning($_.ErrorDetails.Message)
                throw($evar[0].ErrorRecord.Exception.Message)
            }
            "NotFound"
            {
                Write-Warning("Your item wasn't found!")
                throw($evar[0].ErrorRecord.Exception.Message)
            }
            "Forbidden"
            {
                Write-Warning("Your item was forbidden!")
                throw($evar[0].ErrorRecord.Exception.Message)
            }            
            default
            {
                #Write-Warning("Okta RequestID: " + $_.Exception.Response.Headers['X-Okta-Request-Id'])
                Write-Warning($evar[0].ErrorRecord.Exception.GetType().FullName + " : " + $code)
                throw($evar[0].ErrorRecord.Exception.Message)
            }
        }   
    }
    catch
    {
        Write-Warning("Catchall:" + $_.Exception.GetType().FullName + " : " + $_.Exception.Message )
        throw($_.Exception.Message)
    }

    #Process Response Headers, debug, pagination and rate limiting
    if ( $request2 )
    {
        $responseHeaders = $request2.Headers
        foreach ($rh in $responseHeaders.keys)
        {
            if ($resHeaders.Contains($rh))
            {
                Write-Verbose("Res-Hdr: " + $rh + " -> " + $responseHeaders[$rh])
            }
        }
    }

    if ($responseHeaders['X-Okta-Request-Id'])
    {
        Write-Verbose( "Okta Request ID: " + $responseHeaders['X-Okta-Request-Id'] )
    }

    if ($responseHeaders['link'])
    {
        try
        {
            $link = oktaProcessHeaderLink -linkHeader $responseHeaders['link']
        }
        catch
        {
            Write-Warning($_.Exception.Message)
            $link = $false
        }
        if ($link.next)
        {
            $next = $link.next
        } else {
            Write-Verbose("we had a link header, it didn't contain a next link though")
            $next = $false
        }
        Remove-Variable -Name link -Force
    } else {
        $next = $false
    }

    if ( $responseHeaders['X-Rate-Limit-Remaining'] )
    {
        $rateLimt = @{ Reset = $responseHeaders['X-Rate-Limit-Reset']
                       Limit = $responseHeaders['X-Rate-Limit-Limit']
                       Remaining = $responseHeaders['X-Rate-Limit-Remaining']
                     }
    } else {
        $rateLimt = $false
    }

    if ($request2)
    {
        if ($request2.Content)
        {
            Write-Verbose("There was content retured, convert from json string")
            try
            {
                $result = ConvertFrom-Json -InputObject $request2.Content -Verbose:$oktaVerbose
            }
            catch
            {
                Write-Warning($_.Exception.Message)
                $result = $()
                $next = $false
            }
        } else {
            Write-Verbose("There was content retured, don't try to convert it")
            $result = $()
            $next = $false
        }
    } else {
        $result = $()
    }

    if ($rateLimt){ _oktaRateLimitCheck }
    
    return @{ result = $result ; next = $next ; ratelimit = $rateLimt }
}

function _oktaNewCall()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateScript({_testOrg -org $_})][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateSet("Get", "Head", "Post", "Put", "Delete")][String]$method,
        [parameter(Mandatory=$true)][String]$resource,
        [parameter(Mandatory=$false)][Object]$body = @{},
        [parameter(Mandatory=$false)][boolean]$enablePagination = $OktaOrgs[$oOrg].enablePagination,
        [parameter(Mandatory=$false)][Object]$altHeaders,
        [parameter(Mandatory=$false)][ValidateRange(1,10000)][int]$limit,
        [parameter(Mandatory=$false)][boolean]$untrusted=$false
    )

    $headers = New-Object System.Collections.Hashtable
    if (!$untrusted)
    {
        if ($OktaOrgs[$oOrg].encToken)
        {
            $_c = $headers.add('Authorization',('SSWS ' + ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString -string ($OktaOrgs[$oOrg].encToken).ToString()) ) ))))
        } else {
            $_c = $headers.add('Authorization',('SSWS ' + ($OktaOrgs[$oOrg].secToken).ToString()) )
        }
    }
    $_c = $headers.add('Accept-Charset','ISO-8859-1,utf-8')
    $_c = $headers.add('Accept-Language','en-US')
    $_c = $headers.add('Accept-Encoding','deflate,gzip')

    [string]$encoding = "application/json"
    if ($resource -like 'https://*')
    {
        [string]$uri = $resource
    } else {
        [string]$uri = ($OktaOrgs[$oOrg].baseUrl).ToString() + $resource
    }
    #if our altHeaders contains an alternative UserAgent string set it
    if ( ($altHeaders) -and ($altHeaders['UserAgent']) )
    {
        $userAgent = $altHeaders['UserAgent']
        $altHeaders.Remove('UserAgent')
    }

    foreach ($alt in $altHeaders.Keys)
    {
        $_c = $headers.Add($alt,$altHeaders[$alt])
    }

    <#
        .ratelimit = ratelimit headers or false
        .next = a link or false
        .result = psobject
    #>
    $getPages = $true
    [object]$results = @()
    $Global:nextNext = $false
    $next = $false
    
    while ($getPages)
    {
        try
        {
            $response = _oktaMakeCall -method $method -uri $uri -headers $headers -body $body -userAgent $userAgent
        }
        catch
        {
            Write-Warning($_.Exception.Message)
            Write-Warning("Encountered error, returning limited or empty set")
            $response=$false
        }
        
        if ($response)
        {
            $results += $response.result
            $next = $response.next
            if ($response.result -is [array])
            {
                $i_count = $response.result.Count
            } else {
                $i_count = 1
            }
            
        } else {
            $i_count = 0
            $next = $false
        }

        Remove-Variable -Name response -Force

        $r_count = $results.Count
        Write-Verbose("This Page returned: " + $i_count + ", we've seen: " + $r_count + " results so far")

        if ($i_count -eq 0)
        {
            Write-Verbose("0 results returned, i predict an empty page coming up, lets skip it")
            #there nothing was returned, if there is a next link it is empty, if there isn't a nextlink assume the last link is the next link
            $getPages = $false
            if ($next) { $Global:nextNext = $next } else { $Global:nextNext = $uri }
        }

        if ($limit)
        {
            Write-Verbose("We have a limit: " + $limit + " so we'll predict and avoid empty pages")
            if ($i_count -lt $limit) #this would include 0
            {
                Write-Verbose("The number returned: " + $i_count + ", is less than the limit: " + $limit)
                $getPages = $false
                if ($next) { $Global:nextNext = $next } else { $Global:nextNext = $uri }
            }
        }
        if (! $enablePagination)
        {
            $getPages = $false
        }

        if ($next)
        {
            if ($getPages)
            {
                Write-Verbose("We see a valid next link of: " + $next)
                $uri = $next
            } else {
                Write-Verbose("We are not going to fetch the next link of: " + $next)
            }
        } else {
            Write-Verbose("We see no or an invalid next link of: " + $next.ToString())
            $getPages = $false
        }

    } #End While

    return $results
}

function oktaNewUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [string]$login,
        [string]$password,
        [string]$email,
        [string]$firstName,
        [string]$lastName,
        [string]$r_question="What Was your password?",
        [string]$r_answer=(oktaNewPassword),
        [array]$groupIds,
        [object]$additional=@{}
    )
    $psobj = @{
                profile = @{
                    firstName = $firstName    
                    lastName = $lastName
                    email = $email
                    login = $login
                }
                credentials = @{
                    password = @{ value = $password }
                    recovery_question = @{ question = $r_question;answer = $r_answer.ToLower().Replace(" ","")}
                }
              }
    foreach ($attrib in $additional.keys)
    {
        $psobj.profile.add($attrib, $additional.$attrib)
    }
    if ($groupIds)
    {
        $psobj.add("groupIds", $groupIds)
    }
    [string]$method = "Post"
    [string]$resource = "/api/v1/users?activate=True"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaNewUser2()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][string]$login,
        [parameter(Mandatory=$false)][string]$email,
        [parameter(Mandatory=$true)][string]$firstName,
        [parameter(Mandatory=$true)][string]$lastName,
        [parameter(Mandatory=$true)][string]$mobilePhone,
        [parameter(Mandatory=$false)][object]$additional=@{}
    )
    if (!$email){$email=$login}
    $psobj = @{
                profile = @{
                    firstName = $firstName    
                    lastName = $lastName
                    email = $email
                    login = $login
                    mobilePhone = $mobilePhone
                }
              }
    foreach ($attrib in $additional.keys)
    {
        $psobj.profile.add($attrib, $additional.$attrib)
    }
    [string]$method = "Post"
    [string]$resource = "/api/v1/users?activate=False"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaChangeProfilebyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [Parameter(Mandatory=$true)][hashtable]$newprofile
    )

    $psobj = $newprofile
    
    [string]$method = "Put"
    [string]$resource = "/api/v1/users/" + $uid
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaPutProfileupdate()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [object]$updates
    )

    $psobj = New-Object System.Collections.Hashtable
    Add-Member -InputObject $psobj -MemberType NoteProperty -Name profile -Value $updates

    [string]$method = "Put"
    [string]$resource = "/api/v1/users/" + $uid
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaUpdateUserbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [string]$login,
        [string]$password,
        [string]$email,
        [string]$firstName,
        [string]$lastName,
        [string]$mobilePhone,
        [string]$r_question,
        [string]$r_answer
    )
    $psobj = @{
                "profile" = @{
                    "firstName" = $firstName    
                    "lastName" = $lastName
                    "email" = $email
                    "login" = $login
                    "mobilePhone" = $mobilePhone
                }
                "credentials" = @{
                    "password" = @{ "value" = $password }
                    "recovery_question" = @{ "question" = $r_question;"answer" = $r_answer.ToLower().Replace(" ","")}
                }
              }
    
    [string]$method = "Put"
    [string]$resource = "/api/v1/users/" + $uid
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaChangePasswordbyID()
{
   param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [string]$new_password,
        [string]$old_password
    )
    $psobj = @{
                "oldPassword" = @{ "value" = $old_password }
                "newPassword" = @{ "value" = $new_password }
              }

    [string]$method = "Post"
    [string]$resource = "/api/v1/users/" + $uid + "/credentials/change_password"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaAdminExpirePasswordbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [string]$tempPassword=(oktaNewPassword)
    )
    $psobj = @{ "tempPassword" = $tempPassword }

    [string]$method = "Post"
    [string]$resource = "/api/v1/users/" + $uid + "/lifecycle/expire_password?tempPassword=false"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request    
}

function oktaAdminUpdateQandAbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][string]$question,
        [parameter(Mandatory=$true)][string]$answer
    )

    $psobj = @{
                "credentials" = @{
                    "recovery_question" = @{ "question" = $question; "answer" = $answer }
                }
              }
    [string]$method = "Put"
    [string]$resource = "/api/v1/users/" + $uid
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaAdminUpdatePasswordbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [string]$password
    )
    $psobj = @{
                "credentials" = @{
                    "password" = @{ "value" = $password }
                 }
              }
    [string]$method = "Put"
    [string]$resource = "/api/v1/users/" + $uid
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaForgotPasswordbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [string]$r_answer,
        [string]$new_password
    )
    $psobj = @{
                "password" = @{ "value" = $new_password }
                "recovery_question" = @{ "answer" = $r_answer.ToLower().Replace(" ","") }
              }
    [string]$method = "Post"
    [string]$resource = "/api/v1/users/" + $uid + "/credentials/forgot_password"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaCheckCredsOld()
{
    <# 
     .Synopsis
      Used to validate the credentials of a user against Okta

     .Description
      Returns a One-Time token used to establish the users session with Okta. See: https://github.com/okta/api/blob/master/docs/endpoints/sessions.md#create-session

     .Parameter username
      The users okta login value

     .Parameter password
      the users plaintext password to be validated against okta

     .Parameter oOrg
      the alias of the Okta Org (assuming everyone has more than one like I do)

     .Example
      # Check credentials for mbe.gan@gmail.com against the prod okta org
      oktaCheckCreds -oOrg 'prod' -username 'mbe.egan@gmail.com' -password 'Password2'
    #>

    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [Parameter(Mandatory=$true)][string]$username,
        [Parameter(Mandatory=$true)][string]$password
    )
    
    $request = $null
    $psobj = @{
                "password" = $password
                "username" = $username
              }
    [string]$method = "Post"
    [string]$resource = "/api/v1/sessions?additionalFields=cookieToken"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaCheckCreds()
{
    <# 
     .Synopsis
      Used to validate the credentials of a user against Okta

     .Description
      Returns a One-Time token used to establish the users session with Okta. See: https://github.com/okta/api/blob/master/docs/endpoints/sessions.md#create-session

     .Parameter username
      The users okta login value

     .Parameter password
      the users plaintext password to be validated against okta

     .Parameter oOrg
      the alias of the Okta Org (assuming everyone has more than one like I do)

     .Example
      # Check credentials for mbe.gan@gmail.com against the prod okta org
      oktaCheckCreds -oOrg 'prod' -username 'mbe.egan@gmail.com' -password 'Password2'
    #>

    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [Parameter(Mandatory=$false)][string]$username,
        [Parameter(Mandatory=$false)][string]$password,
        [Parameter(Mandatory=$false)][string]$token,
        [Parameter(Mandatory=$false)][string]$audience,
        [Parameter(Mandatory=$false)][ValidateLength(1,2048)][string]$relayState,
        [Parameter(Mandatory=$false)][switch]$multiOptionalFactorEnroll,
        [Parameter(Mandatory=$false)][switch]$warnBeforePasswordExpired,      
        [Parameter(Mandatory=$false)][string]$UserAgent,
        [Parameter(Mandatory=$false)][string]$ipAddress,
        [Parameter(Mandatory=$false)][ValidateLength(1,32)][string]$deviceToken,
        [Parameter(Mandatory=$false)][switch]$untrusted
    )
    
    [string]$method = "Post"
    [string]$resource = "/api/v1/authn"

    if ($deviceToken)
    {
        $context = New-Object hashtable
        $context.Add("deviceToken", $deviceToken)
    }

    if ($multiOptionalFactorEnroll -or $warnBeforePasswordExpired)
    {
        [string[]]$param = "multiOptionalFactorEnroll","warnBeforePasswordExpired"
        $options = New-Object hashtable
        foreach ($p in $param)
        {
            if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
            {
                if ((Get-Variable -Name $p -ValueOnly) -ne "")
                {
                    $options.Add($p,(Get-Variable -Name $p -ValueOnly))
                }
            }
        }
    }

    [string[]]$param = "username","password","audience","relayState","token","options","context"
    $psobj = New-Object hashtable
    foreach ($p in $param)
    {
        if (Get-Variable -Name $p -ErrorAction SilentlyContinue) 
        {
            if ((Get-Variable -Name $p -ValueOnly) -ne "")
            {
                $psobj.Add($p,(Get-Variable -Name $p -ValueOnly))
            }
        }
    }

    $altHeaders = New-Object hashtable
    if ($UserAgent)
    {
        $altHeaders.Add('UserAgent', $UserAgent)
    }
    if ($ipAddress)
    {
        $altHeaders.Add('X-Forwarded-For', $ipAddress)
    }

    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj -altHeaders $altHeaders -untrusted $untrusted
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetUserbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("uid")][ValidateLength(1,100)][String]$userName
    )
    #UrlEncode
    #$uid = [System.Web.HttpUtility]::UrlPathEncode($userName)
    $uid = $userName
    
    [string]$method = "Get"
    [string]$resource = "/api/v1/users/" + $uid
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaDeleteUserbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )

    [string]$method = "Delete"
    [string]$resource = "/api/v1/users/" + $uid
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaSuspendUserbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )

    [string]$method = "Post"
    [string]$resource = "/api/v1/users/" + $uid + "/lifecycle/suspend"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaUnSuspendUserbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )

    [string]$method = "Post"
    [string]$resource = "/api/v1/users/" + $uid + "/lifecycle/unsuspend"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetUsersbyAppID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$false)][switch]$skinny,
        [parameter(Mandatory=$false)][int]$limit=$OktaOrgs[$oOrg].pageSize
    )
    
    [string]$method = "Get"
    if ($skinny)
    {
        [string]$resource = "/api/v1/apps/" + $aid + "/skinny_users?limit=" + $limit
    } else {
        [string]$resource = "/api/v1/apps/" + $aid + "/users?limit=" + $limit
    }
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    
    <#foreach ($appUser in $request)
    {
        if ($skinny)
        {
            $appUser = OktaAppUserfromJson -appUser $appUser -skinny
        } else {
            $appUser = OktaAppUserfromJson -appUser $appUser
        }
    }#>
    return $request
}

function oktaGetUsersbyAppIDWithStatus()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [ValidateSet('STAGED','SYNCING','OUT_OF_SYNC','ERROR')][string]$status,
        [int]$limit=$OktaOrgs[$oOrg].pageSize
    )

    [string]$filter = "status eq " + '"'+$status+'"'
    #$filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    
    [string]$method = "Get"
    [string]$resource = "/api/v1/apps/" + $aid + "/users?filter=" + $filter + "&limit=" + $limit
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaListApps()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateSet('ACTIVE','INACTIVE')][String]$status,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$gid,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [switch]$expand
    )

    #Make sure we don't build too many expressions
    [int]$exp = 0
    if ($uid) { $exp++}
    if ($gid) { $exp++}
    if ($status) { $exp++}
    if ($exp -gt 1)
    {
        throw ("Can only use 1 expression to filter on user, group or active")
    }
            
    [string]$method = "Get"
    [string]$resource = '/api/v1/apps?limit=' + $limit
    
    $doFilter = $false
    if ($status)
    {
        $doFilter = $true
        [string]$filter = "status eq " + '"' + $status + '"'
    }
    if ($gid)
    {
        $doFilter = $true
        [string]$filter = "group.id eq " + '"' + $gid + '"'
        if ($expand)
        {
            $filter += "&expand=group/" + $gid
        }
    }
    if ($uid)
    {
        $doFilter = $true
        [string]$filter = "user.id eq " + '"' + $uid + '"'
        if ($expand)
        {
            $filter += "&expand=user/" + $uid
        }
    }
    if ($doFilter)
    {
        #$filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
        $resource = $resource + "&filter=" + $filter
    }
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($app in $request)
    {
        $app = OktaAppfromJson -app $app
    }
    return $request

    <#
    $active = New-Object System.Collections.ArrayList
    foreach ($app in $request)
    {
        if ($app.status -eq 'ACTIVE')
        {
            $_catch = $active.add($app)
        }
    }
    return $active
    #>
}

function oktaGetActiveApps()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize
    )
            
    return oktaListApps -oOrg $oOrg -status ACTIVE -limit $limit
}

function oktaGetAppGroups()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("AppId","applicationid")][ValidateLength(20,20)][String]$aid
    )
        
    [string]$method = "Get"
    [string]$resource = '/api/v1/apps/' + $aid + '/groups'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }

    return $request
}

function oktaListUsers()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination,
        [parameter(Mandatory=$false)][String]$q,
        [parameter(Mandatory=$false)][String]$search,
        [parameter(Mandatory=$false)][String]$filter
    )
    
    [string]$resource = '/api/v1/users' + '?limit=' + $limit
    [string]$method = "Get"

    if ($q)
    {
        [string]$resource = $resource + "&q=" + $q
    } elseif ($search)
    {
        [string]$resource = $resource + "&search=" + $search
    }
    elseif ($filter)
    {
        [string]$resource = $resource + "&filter=" + $filter
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }

    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaListAdministrators()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination,
        [parameter(Mandatory=$false)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [switch]$groups
    )
    
    [string]$resource = '/api/internal/administrators'
    [string]$method = "Get"

    if ($groups)
    {
        [string]$resource = $resource + "/groups"
    }
    elseif ($limit)
    {
        [string]$resource = $resource + "?limit=" + $limit
    } elseif ($uid)
    {
        [string]$resource = $resource + "/" + $uid
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaListUsersbyStatus()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [ValidateSet('STAGED','PROVISIONED','ACTIVE','RECOVERY','LOCKED_OUT','PASSWORD_EXPIRED','SUSPENDED','DEPROVISIONED')][string]$status,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    [string]$filter = "status eq " + '"'+$status+'"'
    #$filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    [string]$resource = "/api/v1/users?filter=" + $filter + "&limit=" + $limit

    [string]$method = "Get"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaListDeprovisionedUsers()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    return oktaListUsersbyStatus -oOrg $oOrg -status "DEPROVISIONED" -limit $limit -enablePagination $enablePagination
}

function oktaListActiveUsers()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    return oktaListUsersbyStatus -oOrg $oOrg -status ACTIVE -limit $limit -enablePagination $enablePagination
}

function oktaListUsersbyDate()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [ValidateSet('STAGED','PROVISIONED','ACTIVE','RECOVERY','LOCKED_OUT','PASSWORD_EXPIRED','DEPROVISIONED')][string]$status,
        #[ValidateSet('lastUpdated','lastLogin','statusChanged','activated','created','passwordChanged')][string]$field,
        [parameter(Mandatory=$true)][ValidateSet('lastUpdated','activated')][string]$field,
        [parameter(Mandatory=$true)][ValidateSet('gt','lt','eq','between')][string]$operator,
        $date,
        $start,
        $stop,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    if ($operator -eq 'between')
    {
        try
        {
            if ($start -is [DateTime])
            {
                $start = Get-Date $start.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
            if ($stop -is [DateTime])
            {
                $stop = Get-Date $stop.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
        }
        catch
        {
            Throw ("Bad or missing dates in filter")
        }
        [string]$filter = $field + " gt " +  '"'+$start+'" and ' + $field + " lt " + '"'+$stop+'"'
    } else {
        try
        {
            if ($date -is [DateTime])
            {
                $date = Get-Date $date.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
            }
        }
        catch
        {
            Throw ("Bad or missing dates in filter")
        }
        [string]$filter = $field + " " + $operator +" " + '"'+$date+'"'
    }

    if ($status)
    {
        $filter = $filter + " and status eq " + '"'+$status+'"'
    }

    #$filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    [string]$resource = "/api/v1/users?filter=" + $filter + "&limit=" + $limit
    [string]$method = "Get"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaListUsersbyAttribute()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateSet('login','email','firstName','lastName')][string]$field,
        [parameter(Mandatory=$true)][ValidateSet('eq')][string]$operator,
        [parameter(Mandatory=$true)][string]$value,
        [ValidateSet('STAGED','PROVISIONED','ACTIVE','RECOVERY','LOCKED_OUT','PASSWORD_EXPIRED','DEPROVISIONED')][string]$status,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    [string]$filter = "profile." + $field + " " + $operator +" " + '"'+$value+'"'

    if ($status)
    {
        $filter = $filter + " and status eq " + '"'+$status+'"'
    }

    #$filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    [string]$resource = "/api/v1/users?filter=" + $filter + "&limit=" + $limit
    [string]$method = "Get"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaResetPasswordbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [boolean]$sendEmail = $False
    )
    
    [string]$method = "Post"
    [string]$resource = '/api/v1/users/' + $uid + '/lifecycle/reset_password?sendEmail=' + $sendEmail
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($user in $request)
    {
        $user = OktaUserfromJson -user $user
    }
    return $request
}

function oktaConvertUsertoFederation()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateSet('FEDERATION','OKTA')][String]$source='FEDERATION'
    )
    
    [string]$method = "Post"
    [string]$resource = '/api/v1/users/' + $uid + '/lifecycle/reset_password?provider=' + $source + '&sendEmail=false'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    #foreach ($user in $request)
    #{
    #    $user = OktaUserfromJson -user $user
    #}
    return $request
}

function oktaDeactivateUserbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )

    [string]$resource = '/api/v1/users/' + $uid + '/lifecycle/deactivate'
    [string]$method = "Post"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }

    return $request
}

function oktaActivateUserbyId()
{
    param
    (
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$oOrg=$oktaDefOrg,
        [Parameter(Mandatory=$false)]
            [ValidateLength(20,20)][
            string]$uid,
        [parameter(Mandatory=$false)]
            [string]$username
    )
    if (!$uid)
    {
        if ($username)
        {
            $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
        } else {
            throw ("Must send one of uid or username")
        }
    }

    [string]$resource = '/api/v1/users/' + $uid + '/lifecycle/activate?sendEmail=False'
    [string]$method = "Post"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }

    return $request
}

function oktaUpdateApp()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][object]$app
    )

    $psobj = $app

    [string]$resource = "/api/v1/apps/" + $aid
    [string]$method = "Put"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaUpdateAppOverrides()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$false)][String]$ssoAcsUrlOverride,
        [parameter(Mandatory=$false)][String]$audienceOverride,
        [parameter(Mandatory=$false)][String]$recipientOverride,
        [parameter(Mandatory=$false)][String]$destinationOverride
    )

    $app = oktaGetAppbyId -oOrg $oOrg -aid $aid
    
    [string[]]$overrides = "ssoAcsUrlOverride","audienceOverride","recipientOverride","destinationOverride"

    foreach ($override in $overrides)
    {
        if (Get-Variable -Name $override -ErrorAction SilentlyContinue) 
        {
            $app.settings.signOn.$override = (Get-Variable -Name $override -ValueOnly)
        }
    }
    
    $new = @{signOnMode=$app.signOnMode; label=$app.label; name=$app.name; settings=$app.settings}
    
    oktaUpdateApp -oOrg $org -aid $aid -app $new
}

function oktaGetAppbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$aid
    )

    [string]$resource = "/api/v1/apps/" + $aid
    [string]$method = "Get"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetAppsbyUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [switch]$expand
    )

    if ($expand)
    {
        $apps = oktaListApps -oOrg $oOrg -uid $uid -expand
    } else {
        $apps = oktaListApps -oOrg $oOrg -uid $uid
    }

    return $apps
}

function oktaGetAppLinksbyUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )
    [string]$resource = "/api/v1/users/" + $uid + "/appLinks"
    [string]$method = "Get"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDeleteGroupbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid
    )
    
    [string]$resource  = '/api/v1/groups/' + $gid
    [string]$method = "Delete"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaToggleAppAssignfromGroup()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][ValidateSet("Add","Remove")][String]$action
    )
    
    [string]$resource  = '/api/v1/apps/' + $aid + '/groups/' + $gid
    
    if ("Add" -eq $action)
    {
        [string]$method = "Put"
    } else {
        [string]$method = "Delete"
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaCreateGroup()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(1,255)][String]$name,
        [parameter(Mandatory=$false)][ValidateLength(1,1024)][String]$description=$null
    )

    $psobj = @{
        profile = @{
            name = $name    
            description = $description
        }
      }
    
    [string]$resource  = '/api/v1/groups'

    [string]$method = "Post"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetGroupbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("groupId")][ValidateLength(20,20)][String]$gid,
        [parameter(Mandatory=$false)][switch]$expand
    )
    
    [string]$resource  = '/api/v1/groups/' + $gid
    if ($expand)
    {
        $resource += '?expand=app,stats,apps'
    }
    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetGroupStatsbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("groupId")][ValidateLength(20,20)][String]$gid
    )
    
    #[string]$resource  = '/api/v1/groups/' + $gid + '/stats'
    [string]$resource  = '/api/v1/groups/' + $gid + '?expand=stats,app,user,groupPushMapping'
    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetGroupsbyUserId()
{
    param
    (
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg
    )
        
    [string]$resource = "/api/v1/users/" + $uid + "/groups"   
    [string]$method = "Get"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDelUserFromAllGroups()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid
    )
        
    $groups = oktaGetGroupsbyUserId -oOrg $oOrg -uid $uid
    foreach ($og in $groups)
    {
        if ($og.type -eq 'OKTA_GROUP')
        {
            oktaDelUseridfromGroupid -oOrg $oOrg -uid $uid -gid $og.id
        }
    }
}

function oktaGetGroupsbyquery()
{
    param
    (
        [parameter(Mandatory=$true)][String]$query,
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg
    )
    oktaListGroups -oOrg $oOrg -query $query
}

function oktaGetGroupsAll()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg
    )

    oktaListGroups -oOrg $oOrg
}

function oktaListGroups()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][String]$query,
        [parameter(Mandatory=$false)][String]$filter,
        [parameter(Mandatory=$false)][int]$limit=$OktaOrgs[$oOrg].pageSize,
        [parameter(Mandatory=$false)][switch]$expand
    )
       
    [string]$resource = "/api/v1/groups?limit=" + $limit
    if ($query)
    {
        $resource += "&q=" + $query
    }
    if ($filter)
    {
        $resource += "&filter=" + $filter
    }

    if ($expand)
    {
        $resource += "&expand=app,stats"
    }

    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -limit $limit
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetRolesByGroupId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$gid
    )
       
    [string]$resource = "/api/v1/groups/" + $gid + "/roles"
    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetRolesByUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles"
    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaAddUsertoRoles()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [Parameter(Mandatory=$true)][ValidateSet("SUPER_ADMIN","ORG_ADMIN","API_ACCESS_MANAGEMENT_ADMIN","APP_ADMIN","USER_ADMIN","MOBILE_ADMIN","READ_ONLY_ADMIN", "HELP_DESK_ADMIN")][String]$roleType
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles"
    [string]$method = "Post"
    $psobj = @{ "type" = $roleType }
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDelUserFromRoles()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(14,24)][String]$rid
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles/" + $rid
    [string]$method = "Delete"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetRoleTargetsByUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][alias("roleId")][ValidateLength(14,24)][String]$rid
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles/" + $rid + "/targets/groups"
    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaAddRoleTargetsByUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][alias("roleId")][ValidateLength(14,24)][String]$rid,
        [parameter(Mandatory=$true)][alias("groupId")][ValidateLength(20,20)][String]$gid
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles/" + $rid + "/targets/groups/" + $gid
    [string]$method = "Put"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDelRoleTargetsByUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][alias("roleId")][ValidateLength(14,24)][String]$rid,
        [parameter(Mandatory=$true)][alias("groupId")][ValidateLength(20,20)][String]$gid
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles/" + $rid + "/targets/groups/" + $gid
    [string]$method = "Delete"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaAddUseridtoGroupid()
{
    param
    (
        [parameter(Mandatory=$false)]
            [alias("userId")]
            [ValidateLength(20,20)]
            [String]$uid,
        [parameter(Mandatory=$true)]
            [ValidateLength(20,20)]
            [String]$gid,
        [parameter(Mandatory=$false)]
            [ValidateLength(1,100)]
            [String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)]
            [string]$username
    )

    if (!$uid)
    {
        if ($username)
        {
            $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
        } else {
            throw ("Must send one of uid or username")
        }
    }
        
    [string]$resource = "/api/v1/groups/" + $gid + "/users/" + $uid
    [string]$method = "Put"
    try
    {
        $request = _oktaNewCall -resource $resource -method $method -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDelUseridfromGroupid()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid
    )
        
    [string]$resource = "/api/v1/groups/" + $gid + "/users/" + $uid
    [string]$method = "Delete"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDelUseridfromAppid()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid
    )
        
    [string]$resource = "/api/v1/apps/" + $aid + "/users/" + $uid
    [string]$method = "Delete"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetprofilebyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid
    )
    $profile = (oktaGetUserbyID -oOrg $oOrg -uid $uid).profile
    return $profile
}

function oktaGetAppProfilebyUserId()
{
    param
    (
        [parameter(Mandatory=$true)][alias("appid")][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg
    )
        
    [string]$resource = "/api/v1/apps/" + $aid + "/users/" + $uid
    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetMasterProfile()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg
    )
    <#
        currently requires profile master to be defined in Okta_org.ps1
        Need to enhance to 'discover' the profile master. Nothing eloquent
        comes to mind at time of writing.
    #>
    $aid = $oktaOrgs[$oOrg].ProfileMaster
    oktaGetAppProfilebyUserId -aid $aid -uid $uid -oOrg $oOrg
}

function oktaGetGroupMembersbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid,
        [parameter(Mandatory=$false)][switch]$skinny,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )
    if ($skinny)
    {
        [string]$resource = "/api/v1/groups/" + $gid + "/skinny_users?limit=" + $limit
    } else {
        [string]$resource = "/api/v1/groups/" + $gid + "/users?limit=" + $limit
    }
    
    [string]$method = "Get"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDeleteUserfromGroup()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid
    )

    [string]$resource = "/api/v1/groups/" + $gid + "/users/" + $uid
    [string]$method = "Delete"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaSetAppCredentials()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][string]$newuserName,
        [parameter(Mandatory=$false)][string]$newPassword
    )
    
    #$_cur = oktaGetAppProfilebyUserId -aid $aid -uid $uid -oOrg $oOrg
    $credentials = New-Object System.Collections.Hashtable
    if ($newPassword)
    {
        $_c = $credentials.Add('password',$newPassword)
    }
    if ($newuserName) {
        $_c = $credentials.Add('userName',$newuserName)
    }

    $psobj = @{
                'credentials' = $credentials
              }
    [string]$resource = "/api/v1/apps/" + $aid + "/users/" + $uid
    [string]$method = "Post"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaUnlockUserbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )
    [string]$resource = '/api/v1/users/' + $uid + '/lifecycle/unlock'
    [string]$method = "Post"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
        #$request = _oktaOldCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaConvertGroupbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid
    )
    [string]$resource = '/api/internal/groups/' + $gid + '/convert'
    [string]$method = "Post"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaUpdateUserProfilebyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][alias("newProfile","updatedProfile")][object]$Profile,
        [switch]$partial
    )

    $psobj = @{ profile = $Profile }

    if ($partial)
    {
        [string]$method = "Post"
    } else {
        [string]$method = "Put"
    }
    [string]$resource = "/api/v1/users/" + $uid
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaUpdateAppProfilebyUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][alias("newProfile","updatedProfile")][object]$profile,
        [switch]$partial
    )
    
    $psobj = @{ profile = $profile }

    [string]$resource = "/api/v1/apps/" + $aid + "/users/" + $uid

    if ($partial)
    {
        [string]$method = "Post"
    } else {
        [string]$method = "Put"
    }
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaUpdateAppExternalIdbyUserId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][string]$externalId
    )
    

    $psobj = @{ externalId = $externalId }

    [string]$resource = "/api/v1/apps/" + $aid + "/users/" + $uid
    [string]$method = "Post"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaActivateFactorByUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,255)][String]$username,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$true)][ValidateLength(6,6)][String]$passCode

    )

    if (!$uid)
    {
        if ($username)
        {
            $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
        } else {
            throw ("Must send one of uid or username")
        }
    }

    $body = @{ passCode = $passCode }

    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $fid + '/lifecycle/activate'
    [string]$method = "Post"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $body
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaEnrollFactorByUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,255)][String]$username,
        [parameter(Mandatory=$true)][ValidateSet('push','sms','call','token','token:software:totp','token:hardware','question','web','email')][String]$factorType,
        [parameter(Mandatory=$true)][ValidateSet('OKTA','RSA','SYMANTEC','GOOGLE','DUO','YUBICO','DEL_OATH')][String]$provider,
        [parameter(Mandatory=$true)]$factorProfile,
        [parameter(Mandatory=$false)]$verifyData,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$false)][switch]$update,
        [parameter(Mandatory=$false)][switch]$updatePhone,
        [parameter(Mandatory=$false)][switch]$activate
    )

    if (!$uid)
    {
        if ($username)
        {
            $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
        } else {
            throw ("Must send one of uid or username")
        }
    }

    [string]$method = "Post"
    [string]$resource = '/api/v1/users/' + $uid + '/factors'
    $params = New-Object System.Collections.Hashtable

    $body = @{
             factorType = $factorType
             provider = $provider
             profile = $factorProfile
             }
    if ($verifyData)
    {
        $body.Add("verify", $verifyData)
    }
    
    if ($update)
    {
        #$resource = $resource + '/' + $fid
        $body = @{ profile = $factorProfile }
    } elseif ($activate)
    {
        $params.Add("activate",$true)
    }
    if ($updatePhone){$params.Add("updatePhone",$true)}
    
    $resource = oktaBuildURI -resource $resource -params $params
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $body
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaActivateFactorByUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(1,255)][String]$fid,
        [parameter(Mandatory=$false)][ValidateLength(5,20)][String]$passCode
    )

    if ($passCode)
    {
        $body = @{ passCode = $passCode }
    } else {
        $body = $null
    }
    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $fid + '/lifecycle/activate'
    [string]$method = "Post"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $body
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetFactorsbyUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,255)][String]$username,
        [parameter(Mandatory=$false)][switch]$eligible
    )
    if (!$uid)
    {
        if ($username)
        {
            $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
        } else {
            throw ("Must send one of uid or username")
        }
    }
    
    [string]$resource = '/api/v1/users/' + $uid + '/factors'
    if ($eligible)
    {
        $resource = $resource + '/catalog'
    }
    [string]$method = "Get"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetFactorbyUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$fid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $fid
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaResetFactorbyUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$false)][ValidateLength(1,255)][String]$username
    )

    if (!$uid)
    {
        if ($username)
        {
            $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
        } else {
            throw ("Must send one of uid or username")
        }
    }

    [string]$method = "Delete"
    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $fid
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaResetFactorsbyUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,255)][String]$username
    )
    if (!$uid)
    {
        if ($username)
        {
            $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
        } else {
            throw ("Must send one of uid or username")
        }
    }

    $factors = oktaGetFactorsbyUser -oOrg $oOrg -uid $uid
    $freset = New-Object System.Collections.ArrayList
    foreach ($factor in $factors)
    {
        $_c = $freset.add( (oktaResetFactorbyUser -oOrg $oOrg -uid $uid -fid $factor.id) )
        $_c = ""
    }

    return $freset
}

function oktaVerifyOTPbyUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$false)][String]$otp
    )

    if ($otp)
    {
        $psobj = @{ passCode = $otp}
    } else {
        $psobj = @{ }
    }

    [string]$method = "Post"
    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $fid + '/verify'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaAuthnQuestionWithState()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(42,42)][String]$stateToken,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$true)][String]$answer
    )

    $psobj = @{ answer = $answer; stateToken = $stateToken }

    [string]$method = "Post"
    [string]$resource = '/api/v1/authn/factors/' + $fid + '/verify'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaVerifyMFAnswerbyUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$true)][String]$answer
    )

    $psobj = @{ answer = $answer}

    [string]$method = "Post"
    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $fid + '/verify'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaVerifyPushbyUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$username,
        [parameter(Mandatory=$false)][ValidateLength(7,15)][String]$ClientIP,
        [parameter(Mandatory=$false)][ValidateLength(1,1024)][String]$UserAgent,
        [parameter(Mandatory=$false)][PSCustomObject]$SESSION_STEP_UP
    )

    [string]$method = "Post"
    [bool]$untrusted=$false
    if (! $SESSION_STEP_UP)
    {
        if (!$uid)
        {
            if ($username)
            {
                $uid = (oktaGetUserbyID -oOrg $oOrg -userName $username).id
            } else {
                throw ("Must send one of uid or username")
            }
        }
    }

    if (!$fid)
    {
        if ($SESSION_STEP_UP)
        {
            $factors = $SESSION_STEP_UP._embedded.factors
        } else {
            $factors = oktaGetFactorsbyUser -oOrg $oOrg -uid $uid
        }
        $push = $false
        foreach ($factor in $factors)
        {
            if ("push" -eq $factor.factorType)
            {
                $push = $factor
            }
        }
    
        if (!$push)
        {
            throw ("No push factor found for $uid")
        }
        Write-Verbose("Found push factor " + $push.id + " sending push")
        [string]$resource = $push._links.verify.href.Split(".com")[1]
    } else {
        Write-Verbose("Using supplied push factor " + $fid + " sending push")
        [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $fid + '/verify'
    }
    
    if ( ($ClientIP) -or ($UserAgent) )
    {
        $altHeaders = New-Object System.Collections.Hashtable
        if ($UserAgent)
        {
            $altHeaders.Add('UserAgent', $UserAgent)
        }
        if ($ClientIP)
        {
            $altHeaders.Add('X-Forwarded-For', $ClientIP)
        }
    }

    if ($SESSION_STEP_UP)
    {
        $stateToken = $SESSION_STEP_UP.stateToken
        $psobj = @{ stateToken = $stateToken}
        $untrusted=$true
    } else {
        $stateToken=$false
        $psobj = @{}
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -altHeaders $altHeaders -body $psobj -untrusted $untrusted
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }

    Write-Verbose("Push transaction triggered, pulling for status @ :" + $request._links.poll.href)

    $poll = _oktaPollPushLink -factorResult $request -oOrg $oOrg -stateToken $stateToken
    return $poll
}

function _oktaPollPushLink()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        $factorResult,
        $stateToken
    )

    $c = 0
    while ("WAITING" -eq $factorResult.factorResult)
    {
        $c++
        $sleepy = (2 * ($c/2))
        Start-Sleep -Seconds $sleepy
        Write-Verbose("Adaptive sleeping for: " + $sleepy + " Seconds") 
        if ($factorResult._links.poll.hints)
        {
            [string]$method = $factorResult._links.poll.hints.allow[0]
            [string]$resource = $factorResult._links.poll.href
        } else {
            [string]$method = $factorResult._links.next.hints.allow[0]
            [string]$resource = $factorResult._links.next.href
        }
        if ($stateToken)
        {
            $psobj = @{ stateToken = $stateToken}
            [bool]$untrusted = $true
        } else {
            $psobj = @{}
            [bool]$untrusted = $false
        }
        try
        {
            $factorResult = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj -untrusted $untrusted
        }
        catch
        {
            Write-Verbose($_.TargetObject)
            throw $_
        }
        if ($factorResult.factorResult)
        {
            Write-Verbose ($factorResult.factorResult)
        } else {
            Write-Verbose ($factorResult.status)
        }

    }

    <#
    switch ($factorResult.factorResult)
    {

        "SUCCESS"
        {
        }
        "REJECTED"
        {
        }
        "TIMEOUT"
        {
        }
    

        default {$results = $factorResult}
    }
    #>

    return $factorResult
}

function oktaGetUserSchemabyType()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$tid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/user/types/' + $tid + '/schemas'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetAppSchema()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/apps/' + $aid + '/user/schemas'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetAppTypes()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/apps/' + $aid + '/user/types'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetMapping()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$source,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$target
    )

    #if (! (($source) -or ($destination)) )
    #{
    #    throw 'we need something here'
    #}

    [string]$method = "Get"
    if (($source) -and ($target))
    {
        [string]$resource = '/api/internal/v1/mappings?source=' + $source + '&target=' + $target
    } elseif ($source) {
        [string]$resource = '/api/internal/v1/mappings?source=' + $source
    } elseif ($target) {
        [string]$resource = '/api/internal/v1/mappings?target=' + $target
    } else {
        throw 'we need something here'
    }
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetUserSchema()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][String]$sid="default"
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/meta/schemas/user/' + $sid
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetSchemabyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$sid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/user/schemas/' + $sid
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetTypebyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$tid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/user/types/' + $tid
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetTypes()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/user/types'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

################## EVENTS ###########################


function oktaListEvents()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [int]$limit=1000,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination,
        [parameter(Mandatory=$false)][ValidateRange(1,180)][int]$sinceDaysAgo=7,
        [parameter(Mandatory=$false)]$since,
        [parameter(Mandatory=$false)]$until,
        [parameter(Mandatory=$false)]$after,
        [parameter(Mandatory=$false)]$filter,
        [parameter(Mandatory=$false)]$startDate,
        [boolean]$publishedFilter=$true
    )

    if ($startDate)
    {
        if ($startDate -is [DateTime])
        {
            $startDate = Get-Date $startDate.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        } else {
            $startDate = Get-Date (Get-Date $startDate).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
    }

    if ($since)
    {
        if ($since -is [DateTime])
        {
            $since = Get-Date $since.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        } else {
            $since = Get-Date (Get-Date $since).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
    } else {
        $now = (Get-Date).ToUniversalTime()
        $since = Get-Date ($now.AddDays(($sinceDaysAgo*-1))) -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    }

    if ($filter -and $publishedFilter)
    {
        $filter = $filter + ' and published gt "' + $since + '"'
    } elseif ($publishedFilter) {
        $filter = 'published gt "' + $since + '"'
    }

    if ($until -and $publishedFilter)
    {
        if ($until -is [DateTime])
        {
            $until = Get-Date $until.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        } else {
            $until = Get-Date (Get-Date $until).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
    }# elseif ($publishedFilter) {
    #    $until = Get-Date (Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    #}

    if ($until -and $publishedFilter)
    {
        $filter = $filter + ' and published lt "' + $until + '"'
    }

    #$filter = [System.Web.HttpUtility]::UrlPathEncode($filter)

    if ($filter -and $publishedFilter)
    {
        [string]$resource = "/api/v1/events?filter=" + $filter + "&limit=" + $limit
    } elseif ($filter -and $startDate)
    {
        [string]$resource = "/api/v1/events?startDate=" + $startDate + "&filter=" + $filter + "&limit=" + $limit
    } elseif ($startDate)
    {
        [string]$resource = "/api/v1/events?startDate" + $startDate + "&limit=" + $limit    
    } elseif ($filter)
    {
        [string]$resource = "/api/v1/events?filter=" + $filter + "&limit=" + $limit
    } else {
        [string]$resource = "/api/v1/events?limit=" + $limit
    }

    if ($after)
    {
        $resource += "&after=$after"
    }
    [string]$method = "Get"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination -limit $limit
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaListLogs()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateRange(1,1000)][int]$limit,
        [parameter(Mandatory=$false)][ValidateRange(1,180)][int]$sinceDaysAgo,
        [parameter(Mandatory=$false)][ValidateRange(0,180)][int]$untilDaysAgo,
        [parameter(Mandatory=$false)][boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination,
        [parameter(Mandatory=$false)][string]$since,
        [parameter(Mandatory=$false)][string]$until,
        [parameter(Mandatory=$false)][string]$filter,
        [parameter(Mandatory=$false)][ValidateSet("ASCENDING","DESCENDING")][string]$order,
        [parameter(Mandatory=$false)][string]$next
    )

    [string]$resource = "/api/v1/logs"
    $params = New-Object System.Collections.Hashtable
    $uri = [System.UriBuilder]::new("https", "hostplaceholder", 443, $resource)
    
    if ($limit)
    {
        $params.Add("limit",$limit)
    }

    if ($order)
    {
        $params.Add("sortOrder",$order)
    }

    if ($since)
    {
        if ($since -is [DateTime])
        {
            $since = Get-Date $since.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        } else {
            $since = Get-Date (Get-Date $since).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
        $params.Add("since",$since)
    } elseif ($sinceDaysAgo) {
        $now = (Get-Date).ToUniversalTime()
        $since = Get-Date ($now.AddDays(($sinceDaysAgo*-1))) -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        $params.Add("since",$since)
    }

    if ($until)
    {
        if ($until -is [DateTime])
        {
            $until = Get-Date $until.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        } else {
            $until = Get-Date (Get-Date $until).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
        $params.Add("until",$until)
    } elseif ($untilDaysAgo) {
        $now = (Get-Date).ToUniversalTime()
        $until = Get-Date ($now.AddDays(($untilDaysAgo*-1))) -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        $params.Add("until",$until)
    }

    if ($filter)
    {
        $params.Add("filter",$filter)
    }

    if ($next)
    {
        #test next value first
        if ($next.StartsWith(($OktaOrgs.$oOrg.baseUrl + "/api/v1/logs?")))
        {
            $resource = $next    
        } else {
            _oktaThrowError -text ("This is not a valid next link: " + $next.ToString())
        }        
    } else {
        $uri = oktaBuildURIQuery -uri $uri -addParams $params
        $resource = $uri.Path + $uri.Query
        Write-Verbose("Before: " + $resource)
        $resource = [System.Web.HttpUtility]::UrlPathEncode($resource)
        Write-Verbose(" After: " + $resource)
    }

    [string]$method = "Get"
    try
    {
        if ($limit)
        {
            $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination -limit $limit
        } else {
            $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination $enablePagination
        }
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

################## Identity Providers ###########################

function oktaListProviders()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$pid,
        [parameter(Mandatory=$false)][ValidateSet('SAML2','FACEBOOK','GOOGLE','LINKEDIN','MICROSOFT')][String]$type,
        [parameter(Mandatory=$false)][ValidateLength(1,255)][String]$filter
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/idps'

    if ($pid)
    {
        $resource += '/' + $pid
    } elseif ($type)
    {
        $resource += '?type=' + $type
    } elseif ($filter)
    {
        $resource += '?q=' + $filter
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaNewProviderPolicyObject()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateSet('AUTO','CALLOUT','DISABLED')][String]$provUserAction='DISABLED',
        [parameter(Mandatory=$false)][bool]$profileMaster=$false,
        [parameter(Mandatory=$false)][ValidateSet('NONE','APPEND','ASSIGN','SYNC')][String]$provGroupAction='NONE',
        [parameter(Mandatory=$false)][ValidateSet('AUTO','CALLOUT','DISABLED')][String]$accountLinkAction='AUTO',
        [parameter(Mandatory=$false)][array]$accountLinkFilter=@(),
        [parameter(Mandatory=$false)][array]$groupsFilter=@(),
        [parameter(Mandatory=$false)][array]$groupsAssign=@(),
        [parameter(Mandatory=$false)][string]$groupSourceAttrName='Groups',
        [parameter(Mandatory=$false)][ValidateLength(9,1024)][String]$userNameTempalate='idpuser.subjectNameId',
        [parameter(Mandatory=$false)][String]$subjectFilter=$null,
        [parameter(Mandatory=$false)][ValidateSet('EMAIL','USERNAME','USERNAME_OR_EMAIL','CUSTOM_ATTRIBUTE')][String]$subjectMatchType='USERNAME_OR_EMAIL',
        [parameter(Mandatory=$false)][String]$subjectMatchAttr=$null,
        [parameter(Mandatory=$false)][String]$maxClockSwew='120000'
    )

    $groups = @{ action = $provGroupAction; sourceAttributeName = $groupSourceAttrName; filter = $groupsFilter; assignments = $groupsAssign }
    $provisioning = @{ action = $provUserAction; profileMaster = $profileMaster; groups = $groups}

    if ($accountLinkFilter.Count -ge 1)
    {
        $accountLink = @{ action = $accountLinkAction; filter = @{groups = @{include = $accountLinkFilter }} }   
    } else {
        $accountLink = @{ action = $accountLinkAction; filter = $null }
    }
    $userNameTemplateobject = @{ template = $userNameTempalate }
    $subject = @{ userNameTemplate = $userNameTemplateobject; filter = $subjectFilter; matchType = $subjectMatchType; matchAttribute = $subjectMatchAttr }

    $policy = @{ provisioning = $provisioning; accountLink = $accountLink; subject = $subject; maxClockSkew = $maxClockSwew }
    
    return $policy
}

function oktaNewSaml2ProtocolObject()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,36)][String]$kid,
        [parameter(Mandatory=$true)][ValidateLength(11,1014)][String]$ssoURL,
        [parameter(Mandatory=$true)][ValidateLength(1,1024)][String]$idpIssuer,
        [parameter(Mandatory=$false)][ValidateLength(1,1024)][String]$idpAudience=($oktaOrgs.$oOrg.baseUrl + '/saml2/service-provider/sp' + (oktaRandLower -Length 18)),
        [parameter(Mandatory=$false)][ValidateLength(1,512)][String]$ssoDestination=$ssoURL,
        [parameter(Mandatory=$false)][ValidateSet('HTTP-POST','HTTP-Redirect')][String]$ssoBinding='HTTP-POST',
        [parameter(Mandatory=$false)][ValidateSet('HTTP-POST','HTTP-Redirect')][String]$acsBinding='HTTP-POST',
        [parameter(Mandatory=$false)][ValidateSet('INSTANCE','ORG')][String]$acsType='INSTANCE',
        [parameter(Mandatory=$false)][ValidateSet('SHA-256','SHA-1')][String]$algoReqAlgo='SHA-256',
        [parameter(Mandatory=$false)][ValidateSet('REQUEST','NONE')][String]$algoReqScope='REQUEST',
        [parameter(Mandatory=$false)][ValidateSet('SHA-256','SHA-1')][String]$algoResAlgo='SHA-256',
        [parameter(Mandatory=$false)][ValidateSet('RESPONSE','ASSERTION','ANY')][String]$algoResScope='ANY',
        [parameter(Mandatory=$false)]
            [ValidateSet('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
                         'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                         'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
                         'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')]
            [String]$nameFormat='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    )

    $endpoints = @{ sso = @{ url = $ssoURL; binding = $ssoBinding; destination = $ssoDestination }
                    acs = @{ binding = $acsBinding; type = $acsType } 
                  }

    $credentials = @{ trust = @{ issuer = $idpIssuer; audience = $idpAudience; kid = $kid }
                      signing = $null
                    }

    $alReq = @{ signature = @{ algorithm = $algoReqAlgo; scope = $algoReqScope } }
    $alRes = @{ signature = @{ algorithm = $algoResAlgo; scope = $algoResScope } }

    $algorithms = @{ request = $alReq; response = $alRes}

    $settings = @{ nameFormat = $nameFormat }
    
    $protocol = @{ type = 'SAML2'
                   endpoints = $endpoints
                   algorithms = $algorithms
                   credentials = $credentials
                   settings = $settings
                }
    return $protocol
}

function oktaAddProvider()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateSet('SAML2','FACEBOOK','GOOGLE','LINKEDIN','MICROSOFT')][String]$type,
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$name,
        [parameter(Mandatory=$false)][ValidateSet('INACTIVE','ACTIVE')][string]$status='ACTIVE',
        [parameter(Mandatory=$true)][object]$protocolObject,
        [parameter(Mandatory=$true)][object]$policyObject
    )

    [string]$method = "Post"
    [string]$resource = '/api/v1/idps'

    $provider = @{ type = $type
                   name = $name
                   status = $status
                   protocol = $protocolObject
                   policy = $policyObject
                 }

    <#
    $json = $provider | ConvertTo-Json -Depth 10

    $prov = ConvertFrom-Json -InputObject $json
    return $prov
    #>
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $provider
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDeleteProvider()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$pid
    )

    [string]$method = "Delete"
    [string]$resource = '/api/v1/idps'

    $resource += '/' + $pid

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

################## Identity Provider Keys ###########################

function oktaListProviderKeys()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,36)][String]$kid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/idps/credentials/keys'



    if ($kid)
    {
        $resource += '/' + $kid
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaAddProviderKey()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][String]$filepath
    )

    [string]$method = "Post"
    [string]$resource = '/api/v1/idps/credentials/keys'

    try
    {
        $cert = Get-Content -Path $filepath
    }
    catch
    {
        throw $_.Exception
    }

    [string]$x5c = ""
    foreach ($line in $cert)
    {
        if ( ($line -ne '-----BEGIN CERTIFICATE-----') -and ($line -ne '-----END CERTIFICATE-----') )
        {
            $x5c += ($line)
        }
    }
    $x5cs = @( $x5c )
    $psobj = @{ x5c = $x5cs }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDeleteProviderKey()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,36)][String]$kid
    )

    [string]$method = "Delete"
    [string]$resource = '/api/v1/idps/credentials/keys'

    $resource += '/' + $kid

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}


################## Zones ###########################

function oktaListZones()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$zid,
        [parameter(Mandatory=$false)][String]$filter
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/org/zones'

    if ($zid)
    {
        $resource += '/' + $zid
    }
    elseif ($filter)
    {
        $resource += ("?filter=" + $filter)
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaCreateZone()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateSet("IP")][String]$type="IP",
        [parameter(Mandatory=$true)][ValidateLength(1,128)][String]$name
    )

    [string]$method = "Post"
    [string]$resource = '/api/v1/org/zones'


    $cidr=@{"type" = "CIDR";"value" = "132.190.0.0/16"}
    $range = @{"type" = "RANGE";"value" = "132.190.192.10"}
    $gateways = @($cidr)
    $proxies = @($range)
    $request = @{ 
                  type = $type
                  name = $name
                  status = "ACTIVE"
                  system = $false
                  id = $null
                  created = $null
                  lastUpdated = $null
                  gateways = $gateways
                  proxies = $proxies
                }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $request
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaCreateApp()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(1,255)][String]$name,
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$label,
        [parameter(Mandatory=$true)][ValidateSet("BOOKMARK","BASIC_AUTH","BROWSER_PLUGIN","SECURE_PASSWORD_STORE","SAML_2_0","WS_FEDERATION",
        "AUTO_LOGIN","OPENID_CONNECT","Custom")][String]$signOnMode,
        [parameter(Mandatory=$true)][hashtable]$settings,
        [parameter(Mandatory=$false)][hashtable]$visibility,
        [parameter(Mandatory=$false)][array]$features
    )

    [string]$method = "Post"
    [string]$resource = '/api/v1/apps'

    $request = @{ 
                  name = $name
                  label = $label
                  status = "ACTIVE"
                  settings = $settings
                  signOnMode = $signOnMode
                }
    if ($visibility){$request.Add("visibility", $visibility)}
    if ($features){$request.Add("features", $features)}

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $request
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaMakeZoneNet()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateSet("CIDR","RANGE")][String]$type,
        [parameter(Mandatory=$true)][String]$address 
    )

    $obj = New-Object psobject -Property @{"type" = $type;"value" = $address}
    #$range = @{"type" = "RANGE";"value" = "132.190.192.10"}
    return $obj
}

function oktaUpdateZone()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$zid,
        [parameter(Mandatory=$false)][ValidateLength(1,128)][String]$newName,
        [parameter(Mandatory=$false)][ValidateSet("Add","Remove")][String]$action,
        [parameter(Mandatory=$false)][ValidateSet("gateways","proxies")][String]$section,
        [parameter(Mandatory=$false)][object]$net
    )

    [string]$method = "Put"
    [string]$resource = '/api/v1/org/zones/' + $zid

    $current = oktaListZones -zid $zid -oOrg $oOrg
    $eNets = $current.$section
    $newNets = New-Object System.Collections.ArrayList
    $worktoDo=$false

    if ($action -eq "Remove")
    {
        foreach ($eNet in $eNets)
        {
            if ( ($net.type -eq $eNet.type) -and ($net.value -eq $eNet.value) )
            {
                Write-Verbose("Removing " + $eNet.type + " with value of: " + $eNet.value)
                $worktoDo=$true
            } else {
                $_c = $newNets.Add($eNet)
            }
        }
    }

    if ($action -eq "Add")
    {
        $worktoDo=$true
        foreach ($eNet in $eNets)
        {
            if ( ($net.type -eq $eNet.type) -and ($net.value -eq $eNet.value) )
            {
                Write-Verbose("Skipping " + $eNet.type + " with value of: " + $eNet.value)
                $worktoDo=$false
            } else {
                $_c = $newNets.Add($eNet)
            }
        }
        if (($worktoDo) -or ($eNets.Count -lt 1))
        {
            $_c = $newNets.Add($net)
            $worktoDo=$true
        }
    }

    $name = $current.name
    
    if ($newName)
    {
        if (!$newName -eq $current.name)
        {
            $worktoDo = $true
            $name = $newName
        }
    }

    if ($section -eq "gateways")
    {
        $otherSection = "proxies"
    } else {
        $otherSection = "gateways"
    }

    $request = @{ 
                  type = $current.type
                  name = $name
                  system = $current.system
                  status = $current.status
                  $section = $newNets
                  $otherSection= $current.$otherSection
                }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $request
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

################## Orgs ###########################

function oktaListOrgs()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][String]$oid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/orgs'



    if ($oid)
    {
        $resource += '/' + $oid
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaListOANApps()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][String]$appname
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/catalog/apps'



    if ($appname)
    {
        $resource += '/' + $appname
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaListAppsAssignedbyGroupId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("groupId")][ValidateLength(20,20)][String]$gid
    )
    
    [string]$resource  = '/api/v1/groups/' + $gid + '/apps'
    [string]$method = "Get"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaListAppAssignments()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][String]$other
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/appInstances'

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

################## _links ###########################

function oktaFetch_link()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][String]$_link
    )

    try
    {
        $request = _oktaNewCall -method "Get" -resource $_link -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

################## Policies ###########################

function oktaListPolicies()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][int]$limit=20,
        [parameter(Mandatory=$true)][ValidateSet("OKTA_SIGN_ON", "PASSWORD", "MFA_ENROLL")][String]$type,
        [parameter(Mandatory=$false)][switch]$rules,
        [parameter(Mandatory=$false)][string]$pid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/policies'

    if ($pid)
    {
        $resource += '/' + $pid
    }

    $resource += ("?limit=" + $limit)

    if ($type)
    {
        $resource += ("&type=" + $type)
    }

    if ($rules)
    {
        $resource += "&expand=rules"
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

################## GroupRules ###########################

function oktaListGroupRules()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][int]$limit=50,
        [parameter(Mandatory=$false)][string]$grid
    )

    [string]$method = "Get"
    [string]$resource = '/api/v1/groups/rules'

    if ($pid)
    {
        $resource += '/' + $grid
    }

    if ($limit)
    {
        $resource += "?limit=$limit"
    }
    
    if ($rules)
    {
        $resource += "&expand=rules"
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -limit $limit
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

Export-ModuleMember -Function okta* -Alias okta*
