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
    #throw ("::" + $OktaSays.errorCode.ToString() + ":: " + $OktaSays.errorSummary.ToString() )
    #throw $OktaSays
    $formatError = New-Object System.FormatException -ArgumentList ($OktaSays.errorCode + " : " + $OktaSays.errorSummary)
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

function _oktaNewCall()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateScript({_testOrg -org $_})][String]$oOrg,
        [String]$method,
        [String]$resource,
        [Object]$body = @{},
        [boolean]$enablePagination = $OktaOrgs[$oOrg].enablePagination
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
    $request.UserAgent = "oktaSpecific PowerShell script(V2)"
    $request.ConnectionGroupName = '_Okta_'
    $request.KeepAlive = $false
    
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
        $_catch = $request.ServicePoint.CloseConnectionGroup('_Okta_')
        $request = $null
        $response = $null
        $sr = $null
        $outputStream = $null
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
    $request.UserAgent = "oktaSpecific PowerShell script(V2)"
    $request.ConnectionGroupName = '_Okta_'
    $request.KeepAlive = $false

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
        $_catch = $request.ServicePoint.CloseConnectionGroup('_Okta_')
        $request = $null
        $response = $null
        $sr = $null
        $outputStream = $null
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
        [Parameter(Mandatory=$false)][parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
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
    return $request
}

function oktaGetActiveApps()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize
    )
            
    [string]$method = "GET"
    [string]$resource = '/api/v1/apps?limit=' + $limit
    
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

    $active = New-Object System.Collections.ArrayList
    foreach ($app in $request)
    {
        if ($app.status -eq 'ACTIVE')
        {
            $_catch = $active.add($app)
        }
    }
    return $active
}

function oktaGetAppGroups()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid
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

function oktaListUsersbyQuery()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [string]$Query = $null,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )
    
    [string]$resource = '/api/v1/users?filter=status+eq+"ACTIVE"' + '&limit=' + $limit
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

function oktaListUsersbyStatus()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [string]$status,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )
    
    [string]$resource = '/api/v1/users?filter=status+eq+"' + $status + '"&limit=' + $limit
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
    [string]$resource = '/api/v1/apps?filter=user.id+eq+"' + $uid + '"'
    if ($expand)
    {
        $resource += "&expand=user/" + $uid
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
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$gid
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
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
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
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )
        
    $groups = oktaGetGroupsbyUserId -oOrg $oOrg -userId $uid
    foreach ($og in $groups)
    {
        if ($og.type -eq 'OKTA_GROUP')
        {
            oktaDelUseridfromGroupid -oOrg $oOrg -userId $uid -groupId $og.id
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
       
    [string]$resource = "/api/v1/groups?q=" + $query 
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

function oktaGetGroupsAll()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize
    )
       
    [string]$resource = "/api/v1/groups?limit=" + $limit
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
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
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

function oktaAddUseridtoGroupid()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
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

function oktaDelUseridfromAppid()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
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
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid
    )
    $profile = (oktaGetUserbyID -oOrg $oOrg -userId $uid).profile
    return $profile
}

function oktaGetAppProfilebyUserId()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
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

function oktaSetAppidCredentialUsername()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$aid,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$uid,
        [parameter(Mandatory=$true)][string]$newuserName
    )
    
    $_cur = oktaGetAppProfilebyUserId -appid $aid -userid $uid -oOrg $oOrg

    $psobj = @{
                'id'          = $uid
                'scope'       = $_cur.scope
                'credentials' = @{'userName' = $newuserName}
              }
    [string]$resource = "/api/v1/apps/" + $aid + "/users/" + $uid
    [string]$method = "PUT"
    if ($oktaVerbose)
    {
        Write-Host Changing username for aid:$aid uid:$uid from $_cur.credentials.userName to $newusername
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
        [parameter(Mandatory=$true)][object]$UpdatedProfile
    )
    
    $psobj = @{ profile = $UpdatedProfile }

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

function oktaGetProfileMappingBySchema()
{
    param
    (
        [parameter(Mandatory=$true)][ValidateLength(1,100)][String]$oOrg,
        [parameter(Mandatory=$true)][ValidateLength(20,20)][String]$sid
    )

    [string]$method = "GET"
    [string]$resource = '/api/v1/mappings/' + $sid
    
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


Export-ModuleMember -Function okta*