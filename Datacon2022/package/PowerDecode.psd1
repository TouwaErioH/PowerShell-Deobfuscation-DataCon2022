<#
    
______                     ______                   _      
| ___ \                    |  _  \                 | |     
| |_/ /____      _____ _ __| | | |___  ___ ___   __| | ___ 
|  __/ _ \ \ /\ / / _ \ '__| | | / _ \/ __/ _ \ / _` |/ _ \
| | | (_) \ V  V /  __/ |  | |/ /  __/ (_| (_) | (_| |  __/
\_|  \___/ \_/\_/ \___|_|  |___/ \___|\___\___/ \__,_|\___| 
                                                           
              PowerShell Script Decoder

-Version    : 2.6.1    
-Author     : Giuseppe Malandrone 
-Email      : giusemaland@gmail.com
-Linkedin   : linkedin.com/in/giuseppe-malandrone-8b3938130/

#>



@{

# Version number of this module.
ModuleVersion = '2.6.1'

# ID used to uniquely identify this module
GUID = 'd0a9150d-b6a4-4b17-a325-e3a24fed0ab9'

# Author of this module
Author = 'Giuseppe Malandrone'

# Copyright statement for this module
Copyright = 'GNU GENERAL PUBLIC LICENSE Version 3'

# Description of the functionality provided by this module
Description = 'PowerShell script decoder'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = '2.0'

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @('Assembly.format.ps1xml')

# Script files (.ps1) that are run in the caller's environment prior to importing this module
ScriptsToProcess = @('GetScriptFromFileFunctions.ps1','DecodeBase64Functions.ps1','DeObfuscateByOverridingFunctions.ps1','DeObfuscateByRegexFunctions.ps1','MalwareAnalysisFunctions.ps1','GraphicsFunctions.ps1','DatabaseFunctions.ps1','VirusTotalAPI.ps1','Main.ps1')

# Functions to export from this module
FunctionsToExport = '*'

}
