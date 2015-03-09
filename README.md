# Okta-PSModule Documentation
======================

This is the starting point for documentation on my powershell module/wrapper for the Okta API.
This is not to be confused with or in competition with the official Okta [Powershell/CSharp module] (https://github.com/okta/oktasdk-csharp/tree/master/Okta.Core.Automation)

I have been building and adding to this for a few years, and I still need the functionality it provides on a near daily basis. I figured it was time to share.

Contents
--------

### Getting Started
* Installation:
** Download the module (git clone or download the zip)
** Place the module in your PSModulePath hint: write-host write-host $env:PSModulePath
* [Getting an API Token](http://developer.okta.com/docs/getting_started/getting_a_token.html)
 You'll need an API token before you can do much
* Create your org specific settings file, there may be better ways to do this, i couldn't think of any. create a Okta_org.ps1 file
** It should look like
*** example file here

Launch powershell, import-module okta, now test it out.

### Examples
* Get a user
* Create a user
* Get a Group
* Get all users of a group
* Get All users of an App

