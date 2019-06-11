# Okta-PSModule Documentation

This is not to be confused with or in competition with the official Okta [Powershell/CSharp module](https://github.com/okta/oktasdk-csharp/tree/master/Okta.Core.Automation).
This is something I have been building and adding to for a few years. I still need the functionality it provides on a near daily basis so I figured it was time to share.

--------

:information_source: **Disclaimer:** This tool is not an official Okta product and does not qualify for any Okta support.

--------

## Getting Started

### PreReq

1. This Module requires Powershell version 4 or greater (see output from `$PSVersionTable`)

```powershell
PS > $PSVersionTable

Name                           Value
----                           -----
PSVersion                      6.0.0-rc
PSEdition                      Core
GitCommitId                    v6.0.0-rc
OS                             Darwin 17.4.0 Darwin Kernel Version 17.4.0: Sun Dec 17 09:19:54 PST 2017; root:xnu-4570.41.2~1/RELEASE_X86_64
Platform                       Unix
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
WSManStackVersion              3.0
```

2. This Module will run on both Windows and Mac/*nix version of powershell

### Installation

1. Download the module (git clone or download the zip)
2. Place the module in your PSModulePath hint [Read more about PSModulePath Here](https://msdn.microsoft.com/en-us/library/dd878324%28v=vs.85%29.aspx)

```powershell
Write-Host $env:PSModulePath
```

3. Get an API Token for your Okta Org [Getting an API Token](http://developer.okta.com/docs/getting_started/getting_a_token.html)
4. Create a file called Okta_org.ps1 (example content below) and save it in the directory with the Okta.psd1 and Okta.psm1 files.

```powershell
<# Okta_org.ps1 #>
# Verbose will print various informative messages
[Boolean]$oktaVerbose = $true
# define the default Okta Org you want to use, useful if you have more than one.
[String]$oktaDefOrg = "prod"

[Hashtable]$oktaOrgs = @{
                        prod1 = [Hashtable]@{
                                baseUrl  = [String]"https://yourdomain.okta.com"
                                secToken = [String]"yourApiToken"
                                enablePagination = [boolean]$true
                                pageSize = [int]500
                               }
                        prod2 = [Hashtable]@{
                                baseUrl  = [String]"https://yourOtherdomain.okta.com"
                                secToken = [String]"yourOtherApiToken"
                                enablePagination = [boolean]$true
                                pageSize = [int]500
                               }
                        prev = [HashTable]@{
                                baseUrl  = [String]"https://yourDomain.oktapreview.com"
                                secToken = [String]"yourPreviewApiToken"
                                enablePagination = [boolean]$true
                                pageSize = [int]500
                               }
                        }
```

### Example Installation:

1. Open a command prompt

```
cd %userprofile%\Documents\WindowsPowerShell\Modules
git clone https://github.com/mbegan/Okta-PSModule.git Okta
cd Okta
notepad Okta_org.ps1
```

2. Paste the basic format for the Okta_org.ps1 file listed Above.
3. Modify file as required \(Update yourdomain, API Token you generated for that org etc\)
4. Save the file
  
### Basic Usage:

1. Launch powershell \(or even better, the powershell ise\)
2. Import the Okta Module
3. Use
```powershell 
PS C:\> Import-Module Okta

PS C:\> oktaGetUserbyID -oOrg prod -uid mbegan@gmail.com
[ GET https://varian.okta.com/api/v1/users/mbegan@gmail.com ]


id              : 00u103j904jPJACDTXXV
status          : ACTIVE
created         : 2014-12-23T22:50:41.000Z
activated       : 2014-12-23T22:50:41.000Z
statusChanged   : 2014-12-23T22:50:41.000Z
lastLogin       : 2015-01-30T23:48:05.000Z
lastUpdated     : 2015-01-30T23:41:41.000Z
passwordChanged : 2015-01-30T23:41:41.000Z
profile         : @{email=mbegan@gmail.com; firstName=Matt; lastName=Egan; login=mbegan@gmail.com; mobilePhone=; secondEmail=}
credentials     : @{password=; recovery_question=; provider=}
_links          : @{resetPassword=; resetFactors=; expirePassword=; forgotPassword=; changeRecoveryQuestion=; deactivate=; changePassword=}
```
When elements are returned in the API they are powershell objects, you can treat them as such.

An example of something I do often.

```powershell
PS C:\Users\megan> $oktauser = oktaGetUserbyID -oOrg prev -uid mbegan@gmail.com
[ GET https://varian.oktapreview.com/api/v1/users/mbegan@gmail.com ]

PS C:\Users\megan> $groups = oktaGetGroupsbyUserId -oOrg prev -uid $oktauser.id
[ GET https://varian.oktapreview.com/api/v1/users/00u3j3jj2cLstvJL70h7/groups ]

PS C:\Users\megan> foreach ($group in $groups) {write-host $group.profile.name $group.id}
Everyone 00g326179lGHZOYPWXCD
okta.throwaway 00g3hyrge0QfpnvM80h7

PS C:\Users\megan> oktaDeleteUserfromGroup -oOrg prev -uid $oktauser.id -gid $groups[1].id
[ DELETE https://varian.oktapreview.com/api/v1/groups/00g3hyrge0QfpnvM80h7/users/00u3j3jj2cLstvJL70h7 ]
```

Some very basic examples, it can do much more.

It supports pagination, so grabbing ALL of your users or groups is not a problem.

I'll add more details on usage later, if you have a specific use case ask away i'll post an example.

Also browse on over to [Okta community](https://support.okta.com/help/community) for more discussion

## A note about TLS 1.2

Momentum is shifting to clients and servers supporting TLS 1.2.  This plugin is capable of connecting to Okta with TLS 1.2 but doesn't do anything to direct the protocol used rather it relies on the SystemDefault configured for [schannel on the host](https://msdn.microsoft.com/en-us/library/system.net.securityprotocoltype(v=vs.110).aspx)

If you want to force TLS 1.2 make sure your system can actually [support it](https://blogs.perficient.com/microsoft/2016/04/tsl-1-2-and-net-support/).

### force TLS 1.2

If you decide you want to force this module to use TLS1.2 add this code block to your Okta_org.ps1 or your $PROFILE script.

```powershell
try
{
   [Net.ServicePointManager]::SecurityProtocol  = [Net.SecurityProtocolType]::Tls12
}
catch
{
   Write-Warning $_.Exception.Message
}
```

#### Available Commands

- oktaActivateUserbyId
- oktaAddRoleTargetsByUserId
- oktaAddUseridtoGroupid
- oktaAddUsertoRoles
- oktaAdminExpirePasswordbyID
- oktaAdminUpdatePasswordbyID
- oktaAdminUpdateQandAbyID
- oktaAuthnQuestionWithState
- oktaChangePasswordbyID
- oktaChangeProfilebyID
- oktaCheckCreds
- oktaCheckCredsOld
- oktaConvertGroupbyId
- oktaConverttoSecureString
- oktaConvertUsertoFederation
- oktaDeactivateUserbyID
- oktaDeleteGroupbyId
- oktaDeleteUserfromGroup
- oktaDelRoleTargetsByUserId
- oktaDelUserFromAllGroups
- oktaDelUseridfromAppid
- oktaDelUseridfromGroupid
- oktaExternalIdtoGUID
- oktaForgotPasswordbyId
- oktaGetActiveApps
- oktaGetAppbyId
- oktaGetAppGroups
- oktaGetAppLinksbyUserId
- oktaGetAppProfilebyUserId
- oktaGetAppsbyUserId
- oktaGetFactorbyUser
- oktaGetFactorsbyUser
- oktaGetGroupbyId
- oktaGetGroupMembersbyId
- oktaGetGroupsAll
- oktaGetGroupsbyquery
- oktaGetGroupsbyUserId
- oktaGetMasterProfile
- oktaGetprofilebyId
- oktaGetProfileMappingBySchema
- oktaGetRolesByUserId
- oktaGetSchemabyID
- oktaGetTypebyID
- oktaGetTypes
- oktaGetUserbyID
- oktaGetUsersbyAppID
- oktaGetUserSchemabyType
- oktaListActiveUsers
- oktaListDeprovisionedUsers
- oktaListUsers
- oktaListUsersbyAttribute
- oktaListUsersbyDate
- oktaListUsersbyStatus
- oktaNewPassword
- oktaNewUser
- oktaProcessHeaderLink
- oktaPutProfileupdate
- oktaResetFactorbyUser
- oktaResetFactorsbyUser
- oktaResetPasswordbyID
- oktaSetAppidCredentialUsername
- oktaUnlockUserbyId
- oktaUpdateApp
- oktaUpdateAppExternalIdbyUserId
- oktaUpdateAppProfilebyUserId
- oktaUpdateUserbyID
- oktaUpdateUserProfilebyID
- oktaVerifyMFAnswerbyUser
- oktaVerifyOTPbyUser
