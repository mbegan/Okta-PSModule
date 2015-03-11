# Okta-PSModule Documentation
======================

This is not to be confused with or in competition with the official Okta [Powershell/CSharp module] (https://github.com/okta/oktasdk-csharp/tree/master/Okta.Core.Automation).
This is something I have been building and adding to for a few years. I still need the functionality it provides on a near daily basis so I figured it was time to share.

--------

### Getting Started
#Installation:
1. Download the module (git clone or download the zip)
2. Place the module in your PSModulePath hint [Read more about PSModulePath Here] (https://msdn.microsoft.com/en-us/library/dd878324%28v=vs.85%29.aspx)

    ``` powershell
Write-Host $env:PSModulePath
    ```

3. Get an API Token for your Okta Org [Getting an API Token](http://developer.okta.com/docs/getting_started/getting_a_token.html)
4. Create a file called Okta_org.ps1 (example content below) and save it in the directory with the Okta.psd1 and Okta.psm1 files.
    ``` powershell
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

#Example Installation:
1. Open a command prompt

    ``` powershell
cd %userprofile%\Documents\WindowsPowerShell\Modules
git clone https://github.com/mbegan/Okta-PSModule.git Okta
cd Okta
notepad Okta_org.ps1
    ```

2. Paste the basic format for the Okta_org.ps1 file listed below.
3. Modify file as required (Update yourdomain, generate your API Key)
4. Save the file
  
#Basic Usage:
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

Pretty simple example, i do much more.

It supports pagination, so grabbing ALL of your users or groups is not a problem.

I'll add more details on usage later, if you have a specific use case ask away i'll post an example.

### Available Commands
- oktaActivateUserbyId
- oktaAddUseridtoGroupid
- oktaAdminExpirePasswordbyID
- oktaAdminUpdatePasswordbyID
- oktaChangePasswordbyID
- oktaChangeProfilebyID
- oktaCheckCreds
- oktaConvertGroupbyId
- oktaDeactivateUserbyID
- oktaDeleteGroupbyId
- oktaDeleteUserfromGroup
- oktaDelUserFromAllGroups
- oktaDelUseridfromAppid
- oktaDelUseridfromGroupid
- oktaExternalIdtoGUID
- oktaForgotPasswordbyId
- oktaGetActiveApps
- oktaGetAppbyId
- oktaGetAppGroups
- oktaGetAppProfilebyUserId
- oktaGetAppsbyUserId
- oktaGetFactorbyUser
- oktaGetFactorsbyUser
- oktaGetGroupbyId
- oktaGetGroupMembersbyId
- oktaGetGroupsAll
- oktaGetGroupsbyquery
- oktaGetGroupsbyUserId
- oktaGetprofilebyId
- oktaGetUserbyID
- oktaGetUsersbyAppID
- oktaListDeprovisionedUsers
- oktaListUsersbyQuery
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
- oktaUpdateAppExternalIdbyUserId
- oktaUpdateAppProfilebyUserId
- oktaUpdateUserbyID
- oktaUpdateUserProfilebyID
- oktaVerifyMFAnswerbyUser
- oktaVerifyOTPbyUser
