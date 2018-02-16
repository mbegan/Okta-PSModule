@{
# Script module or binary module file associated with this manifest
ModuleToProcess = 'Okta.psm1'

# Version number of this module.
ModuleVersion = '2.4'

# ID used to uniquely identify this module
GUID = 'c43305bd-6cdf-4a38-9b15-79ada42d9b9e'

# Author of this module
Author = 'Matt Egan'

HelpInfoUri  = 'https://github.com/mbegan/Okta-PSModule'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = 'Use as you see fit, credit is always nice'

# Description of the functionality provided by this module
Description = 'This module contains powershell wrappers to leverage the Okta API functions described here http://developer.okta.com/docs/getting_started/design_principles.html'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '1.0'

# Name of the Windows PowerShell host required by this module
PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = '1.0'

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = ''

# Processor architecture (None, X86, Amd64, IA64) required by this module
ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
#RequiredAssemblies = @('')

# Script files (.ps1) that are run in the caller's environment prior to importing this module
ScriptsToProcess = @('Okta_org.ps1')

# Type files (.ps1xml) to be loaded when importing this module
#TypesToProcess = @('')

# Format files (.ps1xml) to be loaded when importing this module
#FormatsToProcess = @('')

# Modules to import as nested modules of the module specified in ModuleToProcess
NestedModules = @()

# Functions to export from this module
FunctionsToExport = 'okta*'

# Cmdlets to export from this module
CmdletsToExport = ''

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList = @('Okta.psm1','Okta.psd1','Okta_org.ps1')

# Private data to pass to the module specified in ModuleToProcess
PrivateData = ''
}