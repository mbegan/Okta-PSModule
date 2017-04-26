#using the httputility from system.web
[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | out-null

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
        [Parameter(Mandatory=$true)][string]$Header=$false,
        [parameter(Mandatory=$false)][bool]$skinny=$false
    )

    if (!$Header){return $false}

    [HashTable]$olinks = @{}

    $links = $Header.Split(",")
    foreach ($link in $links)
    {
        #Yes I know it is a regex, but sometimes they work better
        if ($link.Trim() -match '^<(https://.+)>; rel="(\w+)"$')
        {
            if ( ($skinny) -and (($Matches[2].Trim()) -eq "next") )
            {
                $skinnyNext = $Matches[1].Trim().Replace("/users?","/skinny_users?")
                $olinks.add($Matches[2].Trim(), $skinnyNext)
            } else {
                $olinks.add($Matches[2].Trim(), $Matches[1].Trim())
            }
        }
    }
    return $olinks
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
    [double]$warn = .50
    [double]$thottle = .20
    #how many other calls per second should we assume are there for backoff calculations?
    [int]$cps = 16

    $remain = $rateLimt.Remaining
    $limit = $rateLimt.Limit

    $used = ($remain / $limit)

    $limit_note = "You have $remain out of $limit aka: $used left in the tank"

    if ($used -lt $warn)
    {
        $reset = _oktaRateLimitTimeRemaining -seconds $rateLimt.Reset
        $limit_note = "You have $remain out of $limit aka: $used in the next $reset seconds"
        Write-Warning($limit_note)

        if ($used -lt $thottle)
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

            Write-Warning("Throttling " + $aggr + " for: " + $sleepTime + " milliseconds" )
            sleep -Milliseconds $sleepTime
        }

    } else {
        Write-Verbose($limit_note)
    }
}

$okta_UserAgent = "Okta-PSModule/2.1"
function _oktaNewCall()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateScript({_testOrg -org $_})][String]$oOrg,
        [String]$method,
        [String]$resource,
        [Object]$body = @{},
        [boolean]$enablePagination = $OktaOrgs[$oOrg].enablePagination,
        [Object]$altHeaders,
        [parameter(Mandatory=$false)][bool]$skinny=$false
    )

    $headers = New-Object System.Collections.Hashtable
    if ($OktaOrgs[$oOrg].encToken)
    {
        $_c = $headers.add('Authorization',('SSWS ' + ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString -string ($OktaOrgs[$oOrg].encToken).ToString()) ) ))))
    } else {
        $_c = $headers.add('Authorization',('SSWS ' + ($OktaOrgs[$oOrg].secToken).ToString()) )
    }
    $_c = $headers.add('Accept-Charset','ISO-8859-1,utf-8')
    $_c = $headers.add('Accept-Language','en-US')
    $_c = $headers.add('Accept-Encoding','deflate,gzip')

    [string]$encoding = "application/json"
    if ($resource -like 'https://*')
    {
        [string]$URI = $resource
    } else {
        [string]$URI = ($OktaOrgs[$oOrg].baseUrl).ToString() + $resource
    }
    $request = [System.Net.HttpWebRequest]::CreateHttp($URI)
    $request.Method = $method
    if ($oktaVerbose) { Write-Host '[' $request.Method $request.RequestUri ']' -ForegroundColor Cyan}

    $request.Accept = $encoding

    $request.AutomaticDecompression = @([System.Net.DecompressionMethods]::Deflate, [System.Net.DecompressionMethods]::GZip)
    if ( ($altHeaders) -and ($altHeaders['UserAgent']) )
    {
        $request.UserAgent = $altHeaders['UserAgent']
        $altHeaders.Remove('UserAgent')
    } else {
        $request.UserAgent = $okta_UserAgent
    }

    foreach ($alt in $altHeaders.Keys)
    {
        $_c = $headers.Add($alt,$altHeaders[$alt])
    }
    
    foreach($key in $headers.keys)
    {
        $request.Headers.Add($key, $headers[$key])
    }
 
    if ( ($method -eq "POST") -or ($method -eq "PUT") )
    {
        $postData = ConvertTo-Json $body -Depth 10
        if ($oktaVerbose) { Write-Host $postData -ForegroundColor Cyan }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($postData)
        $request.ContentType = $encoding
        $request.ContentLength = $bytes.Length
                 
        [System.IO.Stream]$outputStream = [System.IO.Stream]$request.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)
        $outputStream.Close()
        Remove-Variable -Name outputStream
    }

    if ($oktaVerbose)
    {
        foreach ($h in $request.Headers.keys)
        {
            if ($h -eq 'Authorization')
            {
                Write-Verbose("Hdr: " + $h + " -> SSWS xXxXxXxxXxxXxXxXxxXx")
            } else {
                Write-Verbose("Hdr: " + $h + " -> " + $request.Headers[$h])
            }
        }
    }
 
    try
    {
        [System.Net.HttpWebResponse]$response = $request.GetResponse()
        
        # Get pagination stuff       
        if ($Hlink = $response.GetResponseHeader('Link'))
        {
            try
            {
                $link = oktaProcessHeaderLink -Header $Hlink -skinny $skinny
            }
            catch
            {
                $link = $false
            }
        } else {
            $link = $false
        }

        #Grab rate limit headers
        if ( ($response.Headers['X-Rate-Limit-Reset']) -and ($response.Headers['X-Rate-Limit-Reset']) -and ($response.Headers['X-Rate-Limit-Reset']) )
        {
            $rateLimt = @{ Reset = $response.Headers['X-Rate-Limit-Reset']
                           Limit = $response.Headers['X-Rate-Limit-Limit']
                           Remaining = $response.Headers['X-Rate-Limit-Remaining']
                         }
        }

        if ($response.Headers['X-Okta-Request-Id'])
        {
            Write-Verbose( "Okta Request ID :" + $response.Headers['X-Okta-Request-Id'] )
        }

        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        
        try
        {
            $psobj = ConvertFrom-Json -InputObject $txt
        }
        catch
        {
            Write-Error $txt
            throw "Json Exception"
        }
    }
    catch [Net.WebException]
    { 
        [System.Net.HttpWebResponse]$response = $_.Exception.Response
        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        _oktaThrowError -text $txt
    }
    catch
    {
        throw $_
    }
    finally
    {
        $response.Close()
        $response.Dispose()
    }

    #Enforce Ratelimiting
    if ($rateLimt)
    {
        _oktaRateLimitCheck
    }

    if (($link.next) -and ($enablePagination))
    {
        if ($oktaVerbose) { Write-Host "fetching next page 1 : " -ForegroundColor Cyan -NoNewline}
        switch ($method)
        {
            'GET'
            {
                _oktaRecGet -url $link.next -col $psobj -oOrg $oOrg -loopcount 1 -skinny $skinny
                continue     
            }
            DEFAULT
            {
                throw ("undefined method for pagination: $method")
            }
        }
    } else {
        return $psobj
    }
}

function _oktaRecGet()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [string]$url,
        [array]$col,
        [int]$loopcount = 0,
        [parameter(Mandatory=$false)][bool]$skinny=$false
    )

    $headers = New-Object System.Collections.Hashtable
    if ($OktaOrgs[$oOrg].encToken)
    {
        $_c = $headers.add('Authorization',('SSWS ' + ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( (ConvertTo-SecureString -string ($OktaOrgs[$oOrg].encToken).ToString()) ) ))))
    } else {
        $_c = $headers.add('Authorization',('SSWS ' + ($OktaOrgs[$oOrg].secToken).ToString()) )
    }
    $_c = $headers.add('Accept-Charset','ISO-8859-1,utf-8')
    $_c = $headers.add('Accept-Language','en-US')
    $_c = $headers.add('Accept-Encoding','gzip,deflate')

    [string]$encoding = "application/json"

    $request = [System.Net.HttpWebRequest]::CreateHttp($url)
    $request.Method = 'GET'
    if ($oktaVerbose) { Write-Host '[' $request.Method $request.RequestUri ']' -ForegroundColor Cyan}

    $request.Accept = $encoding
    $request.UserAgent = $okta_UserAgent
    $request.AutomaticDecompression = @([System.Net.DecompressionMethods]::Deflate, [System.Net.DecompressionMethods]::GZip)

    foreach($key in $headers.keys)
    {
        $request.Headers.Add($key, $headers[$key])
    }
    
    try
    {
        [System.Net.HttpWebResponse]$response = $request.GetResponse()

        if ($Hlink = $response.GetResponseHeader('Link'))
        {
            try
            {
                $link = oktaProcessHeaderLink -Header $Hlink -skinny $skinny
                #Write-Verbose($link)
            }
            catch
            {
                $link = $false
            }
        } else {
            $link = $false
        }

        #Grab rate limit headers
        if ( ($response.Headers['X-Rate-Limit-Reset']) -and ($response.Headers['X-Rate-Limit-Reset']) -and ($response.Headers['X-Rate-Limit-Reset']) )
        {
            $rateLimt = @{ Reset = $response.Headers['X-Rate-Limit-Reset']
                           Limit = $response.Headers['X-Rate-Limit-Limit']
                           Remaining = $response.Headers['X-Rate-Limit-Remaining']
                         }
        }

        if ($response.Headers['X-Okta-Request-Id'])
        {
            Write-Verbose( "Okta Request ID :" + $response.Headers['X-Okta-Request-Id'] )
        }

        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        
        try
        {
            $psobj = ConvertFrom-Json -InputObject $txt
            $col = $col + $psobj
        }
        catch
        {
            throw "Json Exception : " + $txt
        }
    }
    catch [Net.WebException]
    { 
        [System.Net.HttpWebResponse]$response = $_.Exception.Response
        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        _oktaThrowError -text $txt
    }
    catch
    {
        throw $_
    }
    finally
    {
        $response.Close()
        $response.Dispose()
    }

    #Enforce Ratelimiting
    if ($rateLimt)
    {
        _oktaRateLimitCheck
    }

    if ($link.next)
    {
        $loopcount++
        if ($oktaVerbose) { Write-Host "fetching next page $loopcount : " -ForegroundColor Cyan -NoNewline}
        _oktaRecGet -url $link.next -col $col -loopcount $loopcount -oOrg $oOrg -skinny $skinny
    } else {
        return $col
    }
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
    [string]$method = "POST"
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

function oktaChangeProfilebyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [Parameter(Mandatory=$true)][hashtable]$newprofile
    )

    $psobj = $newprofile
    
    [string]$method = "PUT"
    [string]$resource = "/api/v1/users/" + $uid
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj -enablePagination:$true
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

    [string]$method = "PUT"
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
    
    [string]$method = "PUT"
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

    [string]$method = "POST"
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

    [string]$method = "POST"
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
    [string]$method = "PUT"
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
    [string]$method = "PUT"
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
    [string]$method = "POST"
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
    [string]$method = "POST"
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
        [Parameter(Mandatory=$true)][string]$username,
        [Parameter(Mandatory=$true)][string]$password,
        [Parameter(Mandatory=$false)][string]$ipAddress=$null,
        [Parameter(Mandatory=$false)][string]$deviceToken=$null,
        [Parameter(Mandatory=$false)][string]$relayState=$null
    )
    
    $psobj = @{
               "password" = $password
               "username" = $username
               "relayState" = $relayState
               "context" = @{
                             "ipAddress" = $ipAddress
                             "userAgent" = $relayState
                             "deviceToken" = $deviceToken
                             }
              }
    [string]$method = "POST"
    [string]$resource = "/api/v1/authn"
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

function oktaGetUserbyID()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][alias("uid")][ValidateLength(1,100)][String]$userName
    )
    #UrlEncode
    $uid = [System.Web.HttpUtility]::UrlPathEncode($userName)
    
    [string]$method = "GET"
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

    [string]$method = "DELETE"
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

    [string]$method = "POST"
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

    [string]$method = "POST"
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
    
    [string]$method = "GET"
    if ($skinny)
    {
        [string]$resource = "/api/v1/apps/" + $aid + "/skinny_users?limit=" + $limit
    } else {
        [string]$resource = "/api/v1/apps/" + $aid + "/users?limit=" + $limit
    }
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -skinny $skinny
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    foreach ($appUser in $request)
    {
        if ($skinny)
        {
            $appUser = OktaAppUserfromJson -appUser $appUser -skinny
        } else {
            $appUser = OktaAppUserfromJson -appUser $appUser
        }
    }
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
    $filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    
    [string]$method = "GET"
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
            
    [string]$method = "GET"
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
        $filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
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
        
    [string]$method = "GET"
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
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )
    
    [string]$resource = '/api/v1/users' + '?limit=' + $limit
    [string]$method = "GET"
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

function oktaListUsersbyStatus()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [ValidateSet('STAGED','PROVISIONED','ACTIVE','RECOVERY','LOCKED_OUT','PASSWORD_EXPIRED','DEPROVISIONED')][string]$status,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    [string]$filter = "status eq " + '"'+$status+'"'
    $filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    [string]$resource = "/api/v1/users?filter=" + $filter + "&limit=" + $limit

    [string]$method = "GET"
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
        [parameter(Mandatory=$true)][ValidateSet('lastUpdated')][string]$field,
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

    $filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    [string]$resource = "/api/v1/users?filter=" + $filter + "&limit=" + $limit
    [string]$method = "GET"
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

    $filter = [System.Web.HttpUtility]::UrlPathEncode($filter)
    [string]$resource = "/api/v1/users?filter=" + $filter + "&limit=" + $limit
    [string]$method = "GET"
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
    
    [string]$method = "POST"
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
    
    [string]$method = "POST"
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
    [string]$method = "POST"

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
    [string]$method = "POST"
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
    [string]$method = "PUT"
    
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

function oktaGetAppbyId()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid
    )

    [string]$resource = "/api/v1/apps/" + $aid
    [string]$method = "GET"
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
    [string]$method = "GET"

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
    [string]$method = "DELETE"
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
        $resource += '?expand=app,stats'
    }
    [string]$method = "GET"
    
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
    [string]$method = "GET"
    
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
    [string]$method = "GET"
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
        [parameter(Mandatory=$false)][int]$limit=$OktaOrgs[$oOrg].pageSize,
        [parameter(Mandatory=$false)][switch]$expand
    )
       
    [string]$resource = "/api/v1/groups?limit=" + $limit
    if ($query)
    {
        $resource += "&q=" + $query
    }

    if ($expand)
    {
        $resource += "&expand=app,stats"
    }

    [string]$method = "GET"
    
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
    [string]$method = "GET"
    
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
        [Parameter(Mandatory=$true)][ValidateSet("SUPER_ADMIN","ORG_ADMIN","APP_ADMIN","USER_ADMIN","READ_ONLY_ADMIN")][String]$roleType
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles"
    [string]$method = "POST"
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
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$rid
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles/" + $rid
    [string]$method = "DELETE"
    
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
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$rid
    )
       
    [string]$resource = "/api/v1/users/" + $uid + "/roles/" + $rid + "/targets/groups"
    [string]$method = "GET"
    
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
    [string]$method = "PUT"
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
    [string]$method = "DELETE"
    
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
    [string]$method = "DELETE"
    
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
    [string]$method = "GET"
    
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
    
    [string]$method = "GET"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true -skinny $skinny
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
    [string]$method = "DELETE"

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
    [string]$method = "POST"

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
    [string]$method = "POST"
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
    [string]$method = "POST"
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
        [string]$method = "POST"
    } else {
        [string]$method = "PUT"
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
        [string]$method = "POST"
    } else {
        [string]$method = "PUT"
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
    [string]$method = "POST"
    
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
    [string]$method = "POST"

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

function oktaAddFactorByUser()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(1,255)][String]$username,
        [parameter(Mandatory=$false)][ValidateSet('sms','token:hardware')][String]$factorType,
        [parameter(Mandatory=$false)][ValidateSet('OKTA','DUO')][String]$provider,
        [parameter(Mandatory=$false)][String]$phoneNumber,
        [parameter(Mandatory=$false)][ValidateLength(20,20)][String]$fid,
        [parameter(Mandatory=$false)][switch]$update
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

    $profile = @{phoneNumber = $phoneNumber}

    $body = @{
             factorType = $factorType
             provider = $provider
             profile = $profile
             }

    [string]$resource = '/api/v1/users/' + $uid + '/factors'
    [string]$method = "POST"

    if ($update)
    {
        #[string]$method = "PUT"
        $resource = $resource + '/' + $fid
        $body = @{ profile = $profile }
    }

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
    
    [string]$resource = '/api/v1/users/' + $uid + '/factors'
    [string]$method = "GET"
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

    [string]$method = "GET"
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

    [string]$method = "DELETE"
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

    [string]$method = "POST"
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

    [string]$method = "POST"
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

    [string]$method = "POST"
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
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$username,
        [parameter(Mandatory=$false)][ValidateLength(7,15)][String]$ClientIP,
        [parameter(Mandatory=$false)][ValidateLength(1,1024)][String]$UserAgent
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
    $push = $false
    foreach ($factor in $factors)
    {
        if (("push" -eq $factor.factorType) -and ("ACTIVE" -eq $factor.status))
        {
            $push = $factor
        }
    }

    if (!$push)
    {
        throw ("No push factor found for $uid")
    } else {
        Write-Verbose("Found push factor " + $factor.id + " sending push")
    }

    [string]$method = "POST"
    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $push.id + '/verify'
    if ( ($ClientIP -like "*") -or ($UserAgent -like "*") )
    {
        $altHeaders = New-Object System.Collections.Hashtable
        if ($UserAgent -like "*")
        {
            $altHeaders.Add('UserAgent', $UserAgent)
        }
        if ($ClientIP -like "*")
        {
            $altHeaders.Add('X-Forwarded-For', $ClientIP)
        }
    }

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -altHeaders $altHeaders
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

    $poll = _oktaPollPushLink -factorResult $request -oOrg $oOrg
    return $poll
}

function _oktaPollPushLink()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        $factorResult
    )

    $c = 0
    while ("WAITING" -eq $factorResult.factorResult)
    {
        $c++
        $sleepy = (2 * ($c/2))
        sleep -Seconds $sleepy
        Write-Verbose("Adaptive sleeping for: " + $sleepy + " Seconds") 
        [string]$method = $factorResult._links.poll.hints.allow[0]
        [string]$resource = $factorResult._links.poll.href
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
        
        Write-Verbose ($request.factorResult)
        if ($request.factorResult -ne 'WAITING')
        {
            $factorResult = $request
        }
    }

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

    return $results
}

function oktaGetUserSchemabyType()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$tid
    )

    [string]$method = "GET"
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

    [string]$method = "GET"
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

    [string]$method = "GET"
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

    [string]$method = "GET"
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

    [string]$method = "GET"
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

    [string]$method = "GET"
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

    [string]$method = "GET"
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

    [string]$method = "GET"
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
        [int]$limit=100,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination,
        [parameter(Mandatory=$false)][ValidateRange(1,180)][int]$sinceDaysAgo=7,
        $since,
        $until
    )

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

    $filter = 'published gt "' + $since + '" and '

    if ($until)
    {
        if ($until -is [DateTime])
        {
            $until = Get-Date $until.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        } else {
            $until = Get-Date (Get-Date $until).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
    } else {
        $until = Get-Date (Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    }

    $filter = $filter + 'published lt "' + $until + '"'

    $filter = [System.Web.HttpUtility]::UrlPathEncode($filter)

    [string]$resource = "/api/v1/events?filter=" + $filter + "&limit=" + $limit
    [string]$method = "GET"

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

function oktaListLogs()
{
    param
    (
        [parameter(Mandatory=$false)][ValidateLength(1,100)][String]$oOrg=$oktaDefOrg,
        [parameter(Mandatory=$false)][ValidateRange(1,100)][int]$limit=100,
        [parameter(Mandatory=$false)][ValidateRange(1,180)][int]$sinceDaysAgo=7,
        [parameter(Mandatory=$false)][boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination,
        [parameter(Mandatory=$false)][string]$since,
        [parameter(Mandatory=$false)][string]$until,
        [parameter(Mandatory=$false)][ValidateSet("ASCENDING","DECENDING")][string]$order="ASCENDING"
    )

    [string]$resource = "/api/v1/logs?limit=" + $limit + "&sortOrder=" + $order

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

    $resource = $resource + '&since=' + $since

    if ($until)
    {
        if ($until -is [DateTime])
        {
            $until = Get-Date $until.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        } else {
            $until = Get-Date (Get-Date $until).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
        }
    } else {
        $until = Get-Date (Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.fffZ"
    }

    $resource = $resource + '&until=' + $until

    $resource = [System.Web.HttpUtility]::UrlPathEncode($resource)

    [string]$method = "GET"
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

    [string]$method = "GET"
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
    $callout = $null
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

    [string]$method = "POST"
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

    [string]$method = "DELETE"
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

    [string]$method = "GET"
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

    [string]$method = "POST"
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

    [string]$method = "DELETE"
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
        [parameter(Mandatory=$false)][ValidateLength(20,36)][String]$zid
    )

    [string]$method = "GET"
    [string]$resource = '/api/v1/org/zones'



    if ($zid)
    {
        $resource += '/' + $zid
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

    [string]$method = "POST"
    [string]$resource = '/api/v1/org/zones/'


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

    if ($zid)
    {
        $resource += '/' + $zid
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

    [string]$method = "GET"
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

    [string]$method = "GET"
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
    [string]$method = "GET"
    
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

    [string]$method = "GET"
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
        $request = _oktaNewCall -method "GET" -resource $_link -oOrg $oOrg
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