﻿#using the httputility from system.web
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
    return (ConvertFrom-SecureString -SecureString (Get-Credential -Message 'Paste the API Token in Password Box' "User Name Doesn't Matter").Password)
}

function oktaProcessHeaderLink()
{
    param
    (
        [Parameter(Mandatory=$true)][string]$Header=$false
    )

    if (!$Header){return $false}

    [HashTable]$olinks = @{}

    $links = $Header.Split(",")
    foreach ($link in $links)
    {
        #Yes I know it is a regex, but sometimes they work better
        if ($link.Trim() -match '^<(https://.+)>; rel="(\w+)"$')
        {
            $olinks.add($Matches[2].trim(), $Matches[1].trim())
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
        $appUser
    )

    $dateFields = ('created','lastUpdated','statusChanged','passwordChanged','lastSync')

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
        if ($role.$df)
        {
            $role.$df = Get-Date $role.$df
        } else {
            $role.$df = $null
        }
    }
    return $role
}

function _oktaNewCall()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateScript({_testOrg -org $_})][String]$oOrg,
        [String]$method,
        [String]$resource,
        [Object]$body = @{},
        [boolean]$enablePagination = $OktaOrgs[$oOrg].enablePagination,
        [Object]$altHeaders
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

    foreach ($alt in $altHeaders.Keys)
    {
        $_c = $headers.Add($alt,$altHeaders[$alt])
    }

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
    #$request.UserAgent = "Okta-PSModule/2.0"
    $request.UserAgent = "Oktaprise/1.1"
    #$request.KeepAlive = $false
    
    foreach($key in $headers.keys)
    {
        $request.Headers.Add($key, $headers[$key])
    }
 
    if ( ($method -eq "POST") -or ($method -eq "PUT") )
    {
        $postData = ConvertTo-Json $body
        if ($oktaVerbose) { Write-Host $postData -ForegroundColor Cyan }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($postData)
        $request.ContentType = $encoding
        $request.ContentLength = $bytes.Length
                 
        [System.IO.Stream]$outputStream = [System.IO.Stream]$request.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)
        $outputStream.Close()
        Remove-Variable -Name outputStream
    }
 
    try
    {
        [System.Net.HttpWebResponse]$response = $request.GetResponse()
        
        if ($Hlink = $response.GetResponseHeader('Link'))
        {
            try
            {
                $link = oktaProcessHeaderLink -Header $Hlink
            }
            catch
            {
                $link = $false
            }
        } else {
            $link = $false
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
    if (($link.next) -and ($enablePagination))
    {
        if ($oktaVerbose) { Write-Host "fetching next page 1 : " -ForegroundColor Cyan -NoNewline}
        switch ($method)
        {
            'GET'
            {
                _oktaRecGet -url $link.next -col $psobj -oOrg $oOrg -loopcount 1
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
        [int]$loopcount = 0
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
    $request.UserAgent = "Okta-PSModule/2.0"
    #$request.KeepAlive = $false

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
                $link = oktaProcessHeaderLink -Header $Hlink
            }
            catch
            {
                $link = $false
            }
        } else {
            $link = $false
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
    if ($link.next)
    {
        $loopcount++
        if ($oktaVerbose) { Write-Host "fetching next page $loopcount : " -ForegroundColor Cyan -NoNewline}
        _oktaRecGet -url $link.next -col $col -loopcount $loopcount -oOrg $oOrg    
    } else {
        return $col
    }
}

function oktaNewUser()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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

function oktaGetUsersbyAppID()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [int]$limit=$OktaOrgs[$oOrg].pageSize
    )
    
    [string]$method = "GET"
    [string]$resource = "/api/v1/apps/" + $aid + "/users?limit=" + $limit
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
    foreach ($appUser in $request)
    {
        $appUser = OktaAppUserfromJson -appUser $appUser
    }
    return $request
}

function oktaGetUsersbyAppIDWithStatus()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize
    )
            
    return oktaListApps -oOrg $oOrg -status ACTIVE -limit $limit
}

function oktaGetAppGroups()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    return oktaListUsersbyStatus -oOrg $oOrg -status "DEPROVISIONED" -limit $limit -enablePagination $enablePagination
}

function oktaListActiveUsers()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    return oktaListUsersbyStatus -oOrg $oOrg -status ACTIVE -limit $limit -enablePagination $enablePagination
}

function oktaListUsersbyDate()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
                $start = Get-Date $start.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.000Z"
            }
            if ($stop -is [DateTime])
            {
                $stop = Get-Date $stop.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.000Z"
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
                $date = Get-Date $date.ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss.000Z"
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )
    
    [string]$method = "POST"
    [string]$resource = '/api/v1/users/' + $uid + '/lifecycle/reset_password?provider=FEDERATION&sendEmail=false'
    
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

function oktaDeactivateUserbyID()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [Parameter(Mandatory=$True)][string]$uid,
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
    )
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][alias("groupId")][ValidateLength(20,20)][String]$gid
    )
    
    [string]$resource  = '/api/v1/groups/' + $gid
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
    )
    oktaListGroups -oOrg $oOrg -query $query
}

function oktaGetGroupsAll()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
    )

    oktaListGroups -oOrg $oOrg
}

function oktaListGroups()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$false)][String]$query,
        [parameter(Mandatory=$false)][int]$limit=$OktaOrgs[$oOrg].pageSize
    )
       
    [string]$resource = "/api/v1/groups?limit=" + $limit
    if ($query)
    {
        $resource += "&q=" + $query
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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

function oktaAddUseridtoGroupid()
{
    param
    (
        [parameter(Mandatory=$true)][alias("userId")][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid,
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
    )
        
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    [string]$resource = "/api/v1/groups/" + $gid + "/users?limit=" + $limit
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

function oktaDeleteUserfromGroup()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][string]$newuserName,
        [parameter(Mandatory=$false)][string]$newPassword
    )
    
    $_cur = oktaGetAppProfilebyUserId -aid $aid -uid $uid -oOrg $oOrg
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

function oktaUnlockUserbyId()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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

function oktaGetFactorsbyUser()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )
    
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$fid
    )

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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )

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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$false)][ValidateLength(7,15)][String]$ClientIP = '127.0.0.1'
    )
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
    }

    [string]$method = "POST"
    [string]$resource = '/api/v1/users/' + $uid + '/factors/' + $push.id + '/verify'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -altHeaders (@{'X-Forwarded-For' = $ClientIP})
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            Write-Host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }

    $poll = _oktaPollPushLink -factorResult $request -oOrg $oOrg
    return $poll
}

function _oktaPollPushLink()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        $factorResult
    )

    $c = 0
    while ("WAITING" -eq $factorResult.factorResult)
    {
        $c++
        sleep -Seconds (2 * ($c/2))
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
        #Write-Host -BackgroundColor Black -ForegroundColor White $request.factorResult
        if (!("WAITING" -eq $request.factorResult))
        {
            $factorResult = $request
        }
    }
    return $factorResult
}

function oktaGetUserSchemabyType()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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

function oktaGetSchemabyID()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg
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

Export-ModuleMember -Function okta* -Alias okta*