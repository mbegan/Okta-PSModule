#a comment here

#using the httputility from system.web
[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | out-null 

function oktaNewPassword {
# .SYNOPSIS
#   Creates a new complex password.
# .DESCRIPTION
#   Creates a new complex password.
# .PARAMETER Length
#   The minimum password length. The default value is 8.
# .PARAMETER MustIncludeSets
#   The number of character sets which must be included in the password. The default is 3 (of 4).
# .INPUTS
#   System.UInt32
# .OUTPUTS
#   System.String  
# .EXAMPLE
#   oktaNewPassword
# .EXAMPLE
#   oktaNewPassword -Length 30

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
        [string]$externalId
    )
    
    $bytes = [System.Convert]::FromBase64String($externalId)
    $guid = New-Object -TypeName System.Guid -ArgumentList(,$bytes)
    return $guid
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

function _oktaOldCall()
{
    param
    (
        [String]$oOrg = $oktaDefOrg,
        [String]$method,
        [String]$resource,
        [HashTable]$body
    )

    [HashTable]$headers = @{"Authorization" = ("SSWS " + $OktaOrgs[$oOrg].secToken)}
    [string]$contenttype = "application/json"
    [string]$URI = $OktaOrgs[$oOrg].baseUrl + $resource

    if ($method.ToUpper() -eq "GET")
    {
        try
        {
            $result = Invoke-RestMethod -Method $method -Uri $URI -Headers $headers -ContentType $contenttype -ErrorAction SilentlyContinue -Verbose:$oktaVerbose -DisableKeepAlive
        }
        catch
        {
            Write-Error "Invoke-Restmethod failed"
            return $false
        }
    } else {
        $json = ConvertTo-Json -InputObject $body
        if ($oktaVerbose) {write-host $json}

        try
        {
            $result = Invoke-RestMethod -Method $method -Uri $URI -Headers $headers -ContentType $contenttype -Body $json -ErrorAction SilentlyContinue -Verbose:$oktaVerbose -DisableKeepAlive
        }
        catch
        {
            $_|select *
            Throw "Invoke-Restmethod failed " + $_
        }
    }
    return $result
}

function _testOrg()
{
    param
    (
        $org
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
        [ValidateScript({_testOrg -org $_})][String]$oOrg,
        [String]$method,
        [String]$resource,
        [HashTable]$body = @{},
        [boolean]$enablePagination = $OktaOrgs[$oOrg].enablePagination
    )

    [HashTable]$headers = @{ 'Authorization'    =   'SSWS ' + ($OktaOrgs[$oOrg].secToken).ToString()
                             'Accept-Charset'   =   'ISO-8859-1,utf-8'
                             'Accept-Language'  =   'en-US'
                             'Accept-Encoding'  =   'gzip,deflate' }

    [string]$encoding = "application/json"
    if ($resource -like 'https://*')
    {
        [string]$URI = $resource
    } else {
        [string]$URI = ($OktaOrgs[$oOrg].baseUrl).ToString() + $resource
    }
    $request = [System.Net.HttpWebRequest]::CreateHttp($URI)
    $request.Method = $method
    if ($oktaVerbose) { write-host '[' $request.Method $request.RequestUri ']' -ForegroundColor Cyan}

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
        if ($oktaVerbose) { write-host $postData -ForegroundColor Cyan }
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
            Write-Host "Catch 1"
            throw "Json Exception : " + $txt
        }
    }
    catch [Net.WebException]
    { 
        [System.Net.HttpWebResponse]$response = $_.Exception.Response
        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        throw $txt
    }
    catch
    {
        write-host "catch 22?"
        $_ | select *
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
        Write-Host 'looping...'
        switch ($method)
        {
            'GET'
            {
                _oktaRecGet -url $link.next -col $psobj -oOrg $oOrg -loopcount 1  
            }
            DEFAULT
            {
                'I have no case to do what you are asking this'
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
        [string]$oOrg,
        [string]$url,
        [array]$col,
        [int]$loopcount = 0
    )

    [HashTable]$headers = @{ 'Authorization'    =   'SSWS ' + ($OktaOrgs[$oOrg].secToken).ToString()
                             'Accept-Charset'   =   'ISO-8859-1,utf-8'
                             'Accept-Language'  =   'en-US'
                             'Accept-Encoding'  =   'gzip,deflate' }

    [string]$encoding = "application/json"

    $request = [System.Net.HttpWebRequest]::CreateHttp($url)
    $request.Method = 'GET'
    if ($oktaVerbose) { write-host '[' $request.Method $request.RequestUri ']' -ForegroundColor Cyan}

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
            Write-Host "Catch 1"
            throw "Json Exception : " + $txt
        }
    }
    catch [Net.WebException]
    { 
        [System.Net.HttpWebResponse]$response = $_.Exception.Response
        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()
        $sr.Close()
        throw $txt
    }
    catch
    {
        write-host "catch 22?"
        $_ | select *
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
        Write-Host looping: $loopcount
        _oktaRecGet -url $link.next -col $col -loopcount ($loopcount+1) -oOrg $oOrg    
    } else {
        return $col
    }
}

function oktaNewUser()
{
    param
    (
        [string]$oOrg,
        [string]$login,
        [string]$password,
        [string]$email,
        [string]$firstName,
        [string]$lastName,
        [string]$employeeNumber,
        [string]$r_question="What is your password?",
        [string]$r_answer=$password
    )
    $psobj = @{
                "profile" = @{
                    "firstName" = $firstName    
                    "lastName" = $lastName
                    "email" = $email
                    "login" = $login
                    "employeeNumber" = $employeeNumber
                }
                "credentials" = @{
                    "password" = @{ "value" = $password }
                    "recovery_question" = @{ "question" = $r_question;"answer" = $r_answer.ToLower().Replace(" ","")}
                }
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaStringtoGUID()
{
    param
    (
        [string]$string
    )

    $guid = New-Object -TypeName System.Guid -ArgumentList($string)
    return $guid
}

function oktaChangeProfilebyID()
{
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][ValidateScript({$oktaOrgs[$_]})][string]$oOrg,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$userId,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][hashtable]$newprofile
    )

    $psobj = $newprofile
    
    [string]$method = "PUT"
    [string]$resource = "/api/v1/users/" + $userId
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaChangePasswordbyID()
{
   param
    (
        [string]$oOrg,
        [string]$userId,
        [string]$new_password,
        [string]$old_password
    )
    $psobj = @{
                "oldPassword" = @{ "value" = $old_password }
                "newPassword" = @{ "value" = $new_password }
              }

    [string]$method = "POST"
    [string]$resource = "/api/v1/users/" + $userId + "/credentials/change_password"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaAdminUpdatePasswordbyID()
{
    param
    (
        [string]$oOrg,
        [string]$userId,
        [string]$password
    )
    $psobj = @{
                "credentials" = @{
                    "password" = @{ "value" = $password }
                 }
              }
    [string]$method = "PUT"
    [string]$resource = "/api/v1/users/" + $userId
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaForgotPasswordbyId()
{
    param
    (
        [string]$oOrg,
        [string]$userId,
        [string]$r_answer,
        [string]$new_password
    )
    $psobj = @{
                "password" = @{ "value" = $new_password }
                "recovery_question" = @{ "answer" = $r_answer.ToLower().Replace(" ","") }
              }
    [string]$method = "POST"
    [string]$resource = "/api/v1/users/" + $userId + "/credentials/forgot_password"
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
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
        [Parameter(Mandatory=$false)][string]$oOrg,
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetUserbyID()
{
    param
    (
        [string]$oOrg,
        [string]$userId
    )
    #UrlEncode
    $userId = [System.Web.HttpUtility]::UrlPathEncode($userId)
    
    [string]$method = "GET"
    [string]$resource = "/api/v1/users/" + $userId
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetUsersbyAppID()
{
    param
    (
        [string]$oOrg,
        [string]$appId,
        [int]$limit=$OktaOrgs[$oOrg].pageSize
    )
    #UrlEncode
    $userId = [System.Web.HttpUtility]::UrlPathEncode($userId)
    
    [string]$method = "GET"
    [string]$resource = "/api/v1/apps/" + $appId + "/users?limit=" + $limit
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetActiveApps()
{
    param
    (
        [string]$oOrg,
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
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
        [string]$oOrg,
        [string]$AppId
    )
        
    [string]$method = "GET"
    [string]$resource = '/api/v1/apps/' + $AppId + '/groups'
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }

    return $request
}

function oktaListUsersbyQuery()
{
    param
    (
        [string]$oOrg,
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaListUsersbyStatus()
{
    param
    (
        [string]$oOrg,
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}


function oktaListDeprovisionedUsers()
{
    param
    (
        [string]$oOrg,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    return oktaListUsersbyStatus -oOrg $oOrg -status "DEPROVISIONED" -limit $limit -enablePagination $enablePagination
}


function oktaGetPasswordbyID()
{
    param
    (
        [string]$oOrg,
        [string]$userId = $null,
        [boolean]$sendEmail = $False
    )
    
    [string]$method = "POST"
    [string]$resource = '/api/v1/users/' + $userId + '/lifecycle/reset_password?sendEmail=' + $sendEmail
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDeactivateuserbyID()
{
    param
    (
        [string]$oOrg,
        [string]$userId = $null
    )

    [string]$resource = '/api/v1/users/' + $userId + '/lifecycle/deactivate'
    [string]$method = "POST"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaActivateUserbyId()
{
    param
    (
        [Parameter(Mandatory=$True)][string]$userId,
        [string]$oOrg
    )
    [string]$resource = '/api/v1/users/' + $userId + '/lifecycle/activate?sendEmail=False'
    [string]$method = "POST"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetAppbyId()
{
    param
    (
        [string]$oOrg,
        [string]$appid
    )

    [string]$resource = "/api/v1/apps/" + $appid
    [string]$method = "GET"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaGetAppsbyUserId()
{
    param
    (
        [string]$oOrg,
        [string]$userId
    )
    [string]$resource = "/api/v1/users/" + $userId + "/appLinks"
    [string]$method = "GET"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaDeleteGroupbyId()
{
    param
    (
        [string]$oOrg,
        [string]$groupId
    )
    
    [string]$resource  = '/api/v1/groups/' + $groupID
    [string]$method = "DELETE"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaGetGroupbyId()
{
    param
    (
        [string]$oOrg,
        [string]$groupId
    )
    
    [string]$resource  = '/api/v1/groups/' + $groupID
    [string]$method = "GET"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaGetGroupsbyUserId()
{
    param
    (
        [string]$userId,
        [string]$oOrg
    )
        
    [string]$resource = "/api/v1/users/" + $userId + "/groups"   
    [string]$method = "GET"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaDelUserFromAllGroups()
{
    param
    (
        [string]$oOrg,
        [string]$userId
    )
        
    $groups = oktaGetGroupsbyUserId -oOrg $oOrg -userId $userId
    foreach ($og in $groups)
    {
        if ($og.type -eq 'OKTA_GROUP')
        {
            oktaDelUseridfromGroupid -oOrg $oOrg -userId $userId -groupId $og.id
        }
    }
}

function oktaGetGroupsbyquery()
{
    param
    (
        [string]$query,
        [string]$oOrg
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaGetGroupsAll()
{
    param
    (
        [string]$oOrg,
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaAddUseridtoGroupid()
{
    param
    (
        [string]$userId,
        [string]$groupId,
        [string]$oOrg
    )
        
    [string]$resource = "/api/v1/groups/" + $groupId + "/users/" + $userId
    [string]$method = "PUT"
    try
    {
        $request = _oktaNewCall -resource $resource -method $method -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaDelUseridfromGroupid()
{
    param
    (
        [string]$oOrg,
        [string]$userId,
        [string]$groupId
    )
        
    [string]$resource = "/api/v1/groups/" + $groupId + "/users/" + $userId
    [string]$method = "DELETE"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaDelUseridfromAppid()
{
    param
    (
        [string]$oOrg,
        [string]$userId,
        [string]$appId
    )
        
    [string]$resource = "/api/v1/apps/" + $appId + "/users/" + $userId
    [string]$method = "DELETE"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}


function oktaGetprofilebyId()
{
    param
    (
        [string]$oOrg,
        [string]$userId
    )
    $profile = (oktaGetUserbyID -oOrg $oOrg -userId $userId).profile
    return $profile
}

function oktaGetAppProfilebyUserId()
{
    param
    (
        [string]$appid,
        [string]$userid,
        [string]$oOrg
    )
        
    [string]$resource = "/api/v1/apps/" + $appid + "/users/" + $userId
    [string]$method = "GET"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}


function oktaGetGroupMembersbyId()
{
    param
    (
        $oOrg,
        $groupId,
        [int]$limit=$OktaOrgs[$oOrg].pageSize,
        [boolean]$enablePagination=$OktaOrgs[$oOrg].enablePagination
    )

    [string]$resource = "/api/v1/groups/" + $groupId + "/users?limit=" + $limit
    [string]$method = "GET"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -enablePagination:$true
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaDeleteUserfromGroup()
{
    param
    (
        $userId,
        $groupId,
        $oOrg
    )

    [string]$resource = "/api/v1/groups/" + $groupId + "/users/" + $userId
    [string]$method = "DELETE"

    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaSetAppidCredentialUsername()
{
    param
    (
        [string]$oOrg,
        [string]$appid,
        [string]$userid,
        [string]$newuserName
    )
    
    $_cur = oktaGetAppProfilebyUserId -appid $appid -userid $userid -oOrg $oOrg

    $psobj = @{
                'id'          = $userid
                'scope'       = $_cur.scope
                'credentials' = @{'userName' = $newuserName}
              }
    [string]$resource = "/api/v1/apps/" + $appid + "/users/" + $userId
    [string]$method = "PUT"
    if ($oktaVerbose)
    {
        write-host Changing username for aid:$appid uid:$userid from $_cur.credentials.userName to $newusername
    }
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaUnlockUserbyId()
{
    param
    (
        [string]$oOrg,
        [Parameter(Mandatory=$True)][string]$userId
    )
    [string]$resource = '/api/v1/users/' + $userId + '/lifecycle/unlock'
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
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaConvertGroupbyId()
{
    param
    (
        [string]$oOrg,
        [Parameter(Mandatory=$True)][string]$groupId
    )
    [string]$resource = '/api/internal/groups/' + $groupId + '/convert'
    [string]$method = "POST"
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaUpdateUserProfilebyID()
{
    param
    (
        [string]$oOrg,
        [string]$userId,
        [object]$UpdatedProfile
    )

    $psobj = @{ profile = $UpdatedProfile }

    [string]$method = "POST"
    [string]$resource = "/api/v1/users/" + $userId
    try
    {
        $request = _oktaNewCall -oOrg $oOrg -method $method -resource $resource -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $_
    }
    return $request
}

function oktaUpdateAppProfilebyUserId()
{
    param
    (
        [string]$oOrg,
        [string]$appid,
        [string]$userid,
        [object]$UpdatedProfile
    )
    

    $psobj = @{ profile = $UpdatedProfile }

    [string]$resource = "/api/v1/apps/" + $appid + "/users/" + $userId
    [string]$method = "POST"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

function oktaUpdateAppExternalIdbyUserId()
{
    param
    (
        [string]$oOrg,
        [string]$appid,
        [string]$userid,
        [string]$externalId
    )
    

    $psobj = @{ externalId = $externalId }

    [string]$resource = "/api/v1/apps/" + $appid + "/users/" + $userId
    [string]$method = "POST"
    
    try
    {
        $request = _oktaNewCall -method $method -resource $resource -oOrg $oOrg -body $psobj
    }
    catch
    {
        if ($oktaVerbose -eq $true)
        {
            write-host -ForegroundColor red -BackgroundColor white $_.TargetObject
        }
        throw $error[0]
    }
    return $request
}

Export-ModuleMember -Function okta*