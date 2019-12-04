# The Get-TargetResource cmdlet.
function Get-TargetResource
{
    [OutputType([Hashtable])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,
            
        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server   
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                         
        [string]$CertificateThumbPrint      
    )

    try
    {
        $webSite = Get-Website -Name $EndpointName

        if ($webSite)
        {
                # Get Full Path for Web.config file    
            $webConfigFullPath = Join-Path $website.physicalPath "web.config"

            $modulePath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath"
            $ConfigurationPath = Get-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath"

            $UrlPrefix = $website.bindings.Collection[0].protocol + "://"

            $fqdn = $env:COMPUTERNAME
            if ($env:USERDNSDOMAIN)
            {
                $fqdn = $env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
            }

            $iisPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
                        
            $svcFileName = (Get-ChildItem -Path $website.physicalPath -Filter "*.svc").Name

            $serverUrl = $UrlPrefix + $fqdn + ":" + $iisPort + "/" + $webSite.name + "/" + $svcFileName

            $webBinding = Get-WebBinding -Name $EndpointName
            $certificateThumbPrint = $webBinding.certificateHash

            @{
                EndpointName = $EndpointName
                Port = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
                PhysicalPath = $website.physicalPath
                State = $webSite.state
                ModulePath = $modulePath
                ConfigurationPath = $ConfigurationPath
                DSCServerUrl = $serverUrl
                CertificateThumbPrint = $certificateThumbPrint
            }
        }
    }
    catch
    {
        Write-Error "An error occured while retrieving settings for the website"
    }
}

# The Set-TargetResource cmdlet.
function Set-TargetResource
{
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Uint32]$Port = $( if ($IsComplianceServer) { 7070 } else { 8080 } ),

        # Physical path for the IIS Endpoint on the machine (usually under inetpub/wwwroot)                            
        [string]$PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\$EndpointName",

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                            
        [string]$CertificateThumbPrint,

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
    
        # Location on the disk where the Modules are stored            
        [string]$ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules",

        # Location on the disk where the Configuration is stored                    
        [string]$ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration",

        # Is the endpoint for a DSC Compliance Server
        [boolean] $IsComplianceServer
    )

    # Initialize with default values        
    $pathPullServer = "$pshome\modules\PSDesiredStateConfiguration\PullServer"
    $rootDataPath ="$env:PROGRAMFILES\WindowsPowerShell\DscService"
    $jet4provider = "System.Data.OleDb"
    $jet4database = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$env:PROGRAMFILES\WindowsPowerShell\DscService\Devices.mdb;"
    $eseprovider = "ESENT";
    $esedatabase = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Devices.edb";

    $culture = Get-Culture
    $language = $culture.TwoLetterISOLanguageName

    $os = [System.Environment]::OSVersion.Version
    $IsBlue = $false;
    if($os.Major -eq 6 -and $os.Minor -eq 3)
    {
        $IsBlue = $true;
    }

    # Use Pull Server values for defaults
    $webConfigFileName = "$pathPullServer\PSDSCPullServer.config"
    $svcFileName = "$pathPullServer\PSDSCPullServer.svc"
    $pswsMofFileName = "$pathPullServer\PSDSCPullServer.mof"
    $pswsDispatchFileName = "$pathPullServer\PSDSCPullServer.xml"

    # Update only if Compliance Server install is requested
    if ($IsComplianceServer)
    {
        $webConfigFileName = "$pathPullServer\PSDSCComplianceServer.config"
        $svcFileName = "$pathPullServer\PSDSCComplianceServer.svc"
        $pswsMofFileName = "$pathPullServer\PSDSCComplianceServer.mof"
        $pswsDispatchFileName = "$pathPullServer\PSDSCComplianceServer.xml"
    }
                
    Write-Verbose "Create the IIS endpoint"    
    xPSDesiredStateConfiguration\New-PSWSEndpoint -site $EndpointName `
                     -path $PhysicalPath `
                     -cfgfile $webConfigFileName `
                     -port $Port `
                     -applicationPoolIdentityType LocalSystem `
                     -app $EndpointName `
                     -svc $svcFileName `
                     -mof $pswsMofFileName `
                     -dispatch $pswsDispatchFileName `
                     -asax "$pathPullServer\Global.asax" `
                     -dependentBinaries  "$pathPullServer\Microsoft.Powershell.DesiredStateConfiguration.Service.dll" `
                     -language $language `
                     -dependentMUIFiles  "$pathPullServer\$language\Microsoft.Powershell.DesiredStateConfiguration.Service.Resources.dll" `
                     -certificateThumbPrint $CertificateThumbPrint `
                     -EnableFirewallException $true -Verbose

    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "anonymous"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "basic"
    Update-LocationTagInApplicationHostConfigForAuthentication -WebSite $EndpointName -Authentication "windows"
        

    if ($IsBlue)
    {
        Write-Verbose "Set values into the web.config that define the repository for BLUE OS"
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr"-value $esedatabase
    }
    else
    {
        Write-Verbose "Set values into the web.config that define the repository for non-BLUE Downlevel OS"
        $repository = Join-Path "$rootDataPath" "Devices.mdb"
        Copy-Item "$pathPullServer\Devices.mdb" $repository -Force

        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $jet4provider
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $jet4database
    }

    if ($IsComplianceServer)
    {    
        Write-Verbose "Compliance Server: Set values into the web.config that indicate this is the admin endpoint"
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "AdminEndPoint" -value "true"
    }
    else
    {
        Write-Verbose "Pull Server: Set values into the web.config that indicate the location of repository, configuration, modules"

        # Create the application data directory calculated above        
        $null = New-Item -path $rootDataPath -itemType "directory" -Force
                
        # Set values into the web.config that define the repository and where
        # configuration and modules files are stored. Also copy an empty database
        # into place.        
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbprovider" -value $eseprovider
        Set-AppSettingsInWebconfig -path $PhysicalPath -key "dbconnectionstr" -value $esedatabase

        $repository = Join-Path $rootDataPath "Devices.mdb"
        Copy-Item "$pathPullServer\Devices.mdb" $repository -Force

        $null = New-Item -path "$ConfigurationPath" -itemType "directory" -Force

        Set-AppSettingsInWebconfig -path $PhysicalPath -key "ConfigurationPath" -value $ConfigurationPath

        $null = New-Item -path "$ModulePath" -itemType "directory" -Force

        Set-AppSettingsInWebconfig -path $PhysicalPath -key "ModulePath" -value $ModulePath	
    }
}

# The Test-TargetResource cmdlet.
function Test-TargetResource
{
	[OutputType([Boolean])]
    param
    (
        # Prefix of the WCF SVC File
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EndpointName,

        # Port number of the DSC Pull Server IIS Endpoint
        [Uint32]$Port = $( if ($IsComplianceServer) { 7070 } else { 8080 } ),

        # Physical path for the IIS Endpoint on the machine (usually under inetpub/wwwroot)                            
        [string]$PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\$EndpointName",

        # Thumbprint of the Certificate in CERT:\LocalMachine\MY\ for Pull Server
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]                            
        [string]$CertificateThumbPrint = "AllowUnencryptedTraffic",

        [ValidateSet("Present", "Absent")]
        [string]$Ensure = "Present",

        [ValidateSet("Started", "Stopped")]
        [string]$State = "Started",
    
        # Location on the disk where the Modules are stored            
        [string]$ModulePath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Modules",

        # Location on the disk where the Configuration is stored                    
        [string]$ConfigurationPath = "$env:PROGRAMFILES\WindowsPowerShell\DscService\Configuration",

        # Is the endpoint for a DSC Compliance Server
        [boolean] $IsComplianceServer
    )

    $desiredConfigurationMatch = $true;

    $website = Get-Website -Name $EndpointName
    $stop = $true

    Do
    {
        Write-Verbose "Check Ensure"
        if(($Ensure -eq "Present" -and $website -eq $null) -or ($Ensure -eq "Absent" -and $website -ne $null))
        {
            $DesiredConfigurationMatch = $false            
            Write-Verbose "The Website $EndpointName is not present"
            break       
        }

        Write-Verbose "Check Port"
        $actualPort = $website.bindings.Collection[0].bindingInformation.Split(":")[1]
        if ($Port -ne $actualPort)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "Port for the Website $EndpointName does not match the desired state."
            break       
        }

        Write-Verbose "Check Physical Path property"
        if(Test-WebsitePath -EndpointName $EndpointName -PhysicalPath $PhysicalPath)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "Physical Path of Website $EndpointName does not match the desired state."
            break
        }

        Write-Verbose "Check State"
        if($website.state -ne $State -and $State -ne $null)
        {
            $DesiredConfigurationMatch = $false
            Write-Verbose "The state of Website $EndpointName does not match the desired state."
            break      
        }

        Write-Verbose "Get Full Path for Web.config file"
        $webConfigFullPath = Join-Path $website.physicalPath "web.config"
        if ($IsComplianceServer -eq $false)
        {
            Write-Verbose "Check ModulePath"
            if ($ModulePath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ModulePath" -ExpectedAppSettingValue $ModulePath))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }    

            Write-Verbose "Check ConfigurationPath"
            if ($ConfigurationPath)
            {
                if (-not (Test-WebConfigAppSetting -WebConfigFullPath $webConfigFullPath -AppSettingName "ConfigurationPath" -ExpectedAppSettingValue $ConfigurationPath))
                {
                    $DesiredConfigurationMatch = $false
                    break
                }
            }
        }
        $stop = $false
    }
    While($stop)  

    $desiredConfigurationMatch;
}

# Helper function used to validate website path
function Test-WebsitePath
{
    param
    (
        [string] $EndpointName,
        [string] $PhysicalPath
    )

    $pathNeedsUpdating = $false

    if((Get-ItemProperty "IIS:\Sites\$EndpointName" -Name physicalPath) -ne $PhysicalPath)
    {
        $pathNeedsUpdating = $true
    }

    $pathNeedsUpdating
}

# Helper function to Test the specified Web.Config App Setting
function Test-WebConfigAppSetting
{
    param
    (
        [string] $WebConfigFullPath,
        [string] $AppSettingName,
        [string] $ExpectedAppSettingValue
    )
    
    $returnValue = $true

    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement() 

        foreach ($item in $root.appSettings.add) 
        { 
            if( $item.key -eq $AppSettingName ) 
            {                 
                break
            } 
        }

        if($item.value -ne $ExpectedAppSettingValue)
        {
            $returnValue = $false
            Write-Verbose "The state of Web.Config AppSetting $AppSettingName does not match the desired state."
        }

    }
    $returnValue
}

# Helper function to Get the specified Web.Config App Setting
function Get-WebConfigAppSetting
{
    param
    (
        [string] $WebConfigFullPath,
        [string] $AppSettingName
    )
    
    $appSettingValue = ""
    if (Test-Path $WebConfigFullPath)
    {
        $webConfigXml = [xml](get-content $WebConfigFullPath)
        $root = $webConfigXml.get_DocumentElement() 

        foreach ($item in $root.appSettings.add) 
        { 
            if( $item.key -eq $AppSettingName ) 
            {     
                $appSettingValue = $item.value          
                break
            } 
        }        
    }
    
    $appSettingValue
}

# Helper to get current script Folder
function Get-ScriptFolder
{
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}

# Allow this Website to enable/disable specific Auth Schemes by adding <location> tag in applicationhost.config
function Update-LocationTagInApplicationHostConfigForAuthentication
{
    param (
        # Name of the WebSite        
        [String] $WebSite,

        # Authentication Type
        [ValidateSet('anonymous', 'basic', 'windows')]		
        [String] $Authentication
    )

    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null

    $webAdminSrvMgr = new-object Microsoft.Web.Administration.ServerManager

    $appHostConfig = $webAdminSrvMgr.GetApplicationHostConfiguration()

    $authenticationType = $Authentication + "Authentication"
    $appHostConfigSection = $appHostConfig.GetSection("system.webServer/security/authentication/$authenticationType", $WebSite)
    $appHostConfigSection.OverrideMode="Allow"
    $webAdminSrvMgr.CommitChanges()
}

Export-ModuleMember -Function *-TargetResource
















# SIG # Begin signature block
# MIIatQYJKoZIhvcNAQcCoIIapjCCGqICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVGqfdawQhDGV4KnfJ/uJBSD0
# yHygghV6MIIEuzCCA6OgAwIBAgITMwAAAFnWc81RjvAixQAAAAAAWTANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTQwNTIzMTcxMzE1
# WhcNMTUwODIzMTcxMzE1WjCBqzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# DTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpGNTI4LTM3
# NzctOEE3NjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZsTs9oU/3vgN7oi8Sx8H4H
# zh487AyMNYdM6VE6vLawlndC+v88z+Ha4on6bkIAmVsW3QlkOOJS+9+O+pOjPbuH
# j264h8nQYE/PnIKRbZEbchCz2EN8WUpgXcawVdAn2/L2vfIgxiIsnmuLLWzqeATJ
# S8FwCee2Ha+ajAY/eHD6du7SJBR2sq4gKIMcqfBIkj+ihfeDysVR0JUgA3nSV7wT
# tU64tGxWH1MeFbvPMD/9OwHNX3Jo98rzmWYzqF0ijx1uytpl0iscJKyffKkQioXi
# bS5cSv1JuXtAsVPG30e5syNOIkcc08G5SXZCcs6Qhg4k9cI8uQk2P6hTXFb+X2EC
# AwEAAaOCAQkwggEFMB0GA1UdDgQWBBRbKBqzzXUNYz39mfWbFQJIGsumrDAfBgNV
# HSMEGDAWgBQjNPjZUkZwCu1A+3b7syuwwzWzDzBUBgNVHR8ETTBLMEmgR6BFhkNo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNyb3Nv
# ZnRUaW1lU3RhbXBQQ0EuY3JsMFgGCCsGAQUFBwEBBEwwSjBIBggrBgEFBQcwAoY8
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3NvZnRUaW1l
# U3RhbXBQQ0EuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBBQUA
# A4IBAQB68A30RWw0lg538OLAQgVh94jTev2I1af193/yCPbV/cvKdHzbCanf1hUH
# mb/QPoeEYnvCBo7Ki2jiPd+eWsWMsqlc/lliJvXX+Xi2brQKkGVm6VEI8XzJo7cE
# N0bF54I+KFzvT3Gk57ElWuVDVDMIf6SwVS3RgnBIESANJoEO7wYldKuFw8OM4hRf
# 6AVUj7qGiaqWrpRiJfmvaYgKDLFRxAnvuIB8U5B5u+mP0EjwYsiZ8WU0O/fOtftm
# mLmiWZldPpWfFL81tPuYciQpDPO6BHqCOftGzfHgsha8fSD4nDkVJaEmLdaLgb3G
# vbCdVP5HC18tTir0h+q1D7W37ZIpMIIE7DCCA9SgAwIBAgITMwAAAMps1TISNcTh
# VQABAAAAyjANBgkqhkiG9w0BAQUFADB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBD
# QTAeFw0xNDA0MjIxNzM5MDBaFw0xNTA3MjIxNzM5MDBaMIGDMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMR4wHAYDVQQD
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQCWcV3tBkb6hMudW7dGx7DhtBE5A62xFXNgnOuntm4aPD//ZeM08aal
# IV5WmWxY5JKhClzC09xSLwxlmiBhQFMxnGyPIX26+f4TUFJglTpbuVildGFBqZTg
# rSZOTKGXcEknXnxnyk8ecYRGvB1LtuIPxcYnyQfmegqlFwAZTHBFOC2BtFCqxWfR
# +nm8xcyhcpv0JTSY+FTfEjk4Ei+ka6Wafsdi0dzP7T00+LnfNTC67HkyqeGprFVN
# TH9MVsMTC3bxB/nMR6z7iNVSpR4o+j0tz8+EmIZxZRHPhckJRIbhb+ex/KxARKWp
# iyM/gkmd1ZZZUBNZGHP/QwytK9R/MEBnAgMBAAGjggFgMIIBXDATBgNVHSUEDDAK
# BggrBgEFBQcDAzAdBgNVHQ4EFgQUH17iXVCNVoa+SjzPBOinh7XLv4MwUQYDVR0R
# BEowSKRGMEQxDTALBgNVBAsTBE1PUFIxMzAxBgNVBAUTKjMxNTk1K2I0MjE4ZjEz
# LTZmY2EtNDkwZi05YzQ3LTNmYzU1N2RmYzQ0MDAfBgNVHSMEGDAWgBTLEejK0rQW
# WAHJNy4zFha5TJoKHzBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0FfMDgtMzEtMjAx
# MC5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BDQV8wOC0zMS0yMDEwLmNy
# dDANBgkqhkiG9w0BAQUFAAOCAQEAd1zr15E9zb17g9mFqbBDnXN8F8kP7Tbbx7Us
# G177VAU6g3FAgQmit3EmXtZ9tmw7yapfXQMYKh0nfgfpxWUftc8Nt1THKDhaiOd7
# wRm2VjK64szLk9uvbg9dRPXUsO8b1U7Brw7vIJvy4f4nXejF/2H2GdIoCiKd381w
# gp4YctgjzHosQ+7/6sDg5h2qnpczAFJvB7jTiGzepAY1p8JThmURdwmPNVm52Iao
# AP74MX0s9IwFncDB1XdybOlNWSaD8cKyiFeTNQB8UCu8Wfz+HCk4gtPeUpdFKRhO
# lludul8bo/EnUOoHlehtNA04V9w3KDWVOjic1O1qhV0OIhFeezCCBbwwggOkoAMC
# AQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEFBQAwXzETMBEGCgmSJomT8ixkARkW
# A2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9z
# b2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDgzMTIyMTkzMloX
# DTIwMDgzMTIyMjkzMloweTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2aYCAgQpl2U2w+G9Zv
# zMvx6mv+lxYQ4N86dIMaty+gMuz/3sJCTiPVcgDbNVcKicquIEn08GisTUuNpb15
# S3GbRwfa/SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiXGqelcnNW8ReU5P01
# lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJpL9oZC/6SdCnidi9U3RQwWfjSjWL9y8lf
# RjFQuScT5EAwz3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUyt0vXT2Pn0i1i8UU9
# 56wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdcpReejcsRj1Y8wawJXwPTAgMBAAGj
# ggFeMIIBWjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLEejK0rQWWAHJNy4z
# Fha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEE
# AYI3FQIEFgQU/dExTtMmipXhmGA7qDFvpjy82C0wGQYJKwYBBAGCNxQCBAweCgBT
# AHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8KuEKU5VZ5KQwUAYDVR0f
# BEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUFBwEBBEgwRjBEBggr
# BgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNy
# b3NvZnRSb290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIBAFk5Pn8mRq/rb0Cx
# MrVq6w4vbqhJ9+tfde1MOy3XQ60L/svpLTGjI8x8UJiAIV2sPS9MuqKoVpzjcLu4
# tPh5tUly9z7qQX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gNogOlVuC4iktX8pVC
# nPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y4k74jKHK6BOlkU7IG9KPcpUqcW2b
# Gvgc8FPWZ8wi/1wdzaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQvX/TartSCMm78pJUT
# 5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q70eFW6NB4lhhcyTUWX92THUmO
# Lb6tNEQc7hAVGgBd3TVbIc6YxwnuhQ6MT20OE049fClInHLR82zKwexwo1eSV32U
# jaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKNMxZlHg6K3RDeZPRvzkbU
# 0xfpecQEtNP7LN8fip6sCvsTJ0Ct5PnhqX9GuwdgR2VgQE6wQuxO7bN2edgKNAlt
# HIAxH+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJjdibIa4NXJzwoq6G
# aIMMai27dmsAHZat8hZ79haDJLmIz2qoRzEvmtzjcT3XAH5iR9HOiMm4GPoOco3B
# oz2vAkBq/2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIKYRZoNAAAAAAAHDAN
# BgkqhkiG9w0BAQUFADBfMRMwEQYKCZImiZPyLGQBGRYDY29tMRkwFwYKCZImiZPy
# LGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1MzA5WhcNMjEwNDAzMTMwMzA5WjB3
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhN
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7dGE4kD+7Rp9FMrXQwIBHr
# B9VUlRVJlBtCkq6YXDAm2gBr6Hu97IkHD/cOBJjwicwfyzMkh53y9GccLPx754gd
# 6udOo6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDlKEYuJ6yGT1VSDOQD
# LPtqkJAwbofzWTCd+n7Wl7PoIZd++NIT8wi3U21StEWQn0gASkdmEScpZqiX5NMG
# gUqi+YSnEUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1Un68eeEExd8yb3zuD
# k6FhArUdDbH895uyAc4iS1T/+QXDwiALAgMBAAGjggGrMIIBpzAPBgNVHRMBAf8E
# BTADAQH/MB0GA1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWzDzALBgNVHQ8EBAMC
# AYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1UdIwSBkDCBjYAUDqyCYEBWJ5flJRP8
# KuEKU5VZ5KShY6RhMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJkiaJk/Is
# ZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eYIQea0WoUqgpa1Mc1j0BxMuZTBQBgNVHR8ESTBHMEWgQ6BB
# hj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9taWNy
# b3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEESDBGMEQGCCsGAQUFBzAChjho
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jvc29mdFJvb3RD
# ZXJ0LmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAgEA
# EJeKw1wDRDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQSooxtYrhXAstOIBNQ
# md16QOJXu69YmhzhHQGGrLt48ovQ7DsB7uK+jwoFyI1I4vBTFd1Pq5Lk541q1YDB
# 5pTyBi+FA+mRKiQicPv2/OR4mS4N9wficLwYTp2OawpylbihOZxnLcVRDupiXD8W
# mIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPfwgphjvDXuBfrTot/xTUrXqO/67x9
# C0J71FNyIe4wyrt4ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWGzFFW6J1wlGysOUzU
# 9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89Ds+X57H2146SodDW4TsVxIxIm
# dgs8UoxxWkZDFLyzs7BNZ8ifQv+AeSGAnhUwZuhCEl4ayJ4iIdBD6Svpu/RIzCzU
# 2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LBJ1S2sWo9iaF2YbRuoROm
# v6pH8BJv/YoybLL+31HIjCPJZr2dHYcSZAI9La9Zj7jkIeW1sMpjtHhUBdRBLlCs
# lLCleKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/Jmu5J4PcBZW+JC33I
# acjmbuqnl84xKf8OxVtc2E0bodj6L54/LlUWa8kTo/0xggSlMIIEoQIBATCBkDB5
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQDExpN
# aWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQQITMwAAAMps1TISNcThVQABAAAAyjAJ
# BgUrDgMCGgUAoIG+MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSSYrtb3NWiKIAV
# bCUbwMgrmLM5ZjBeBgorBgEEAYI3AgEMMVAwTqAmgCQATQBpAGMAcgBvAHMAbwBm
# AHQAIABMAGUAYQByAG4AaQBuAGehJIAiaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L2xlYXJuaW5nIDANBgkqhkiG9w0BAQEFAASCAQBZcpaN0x5SS28rxUFd/RXt9RYE
# GpXpG4cs9oTG+ue/OTE6wym+E9GTxJMcu5pP1+pTE8McRY4aDBd+qGD/utnz7HoK
# PR1TN2LHs8BaVDSXSa/aFEUvDySwgT4rGQ2Ink+q3VtIOcXpwk/moM8nvDLTM4ot
# neigohU/jZbnvZ7/MjNpDHox68kVzOIOqH1V127DygHr9ewOMMRcL6xznoA+YGfj
# z/PdBg0YWJW47nFX7jd/FRnbjR+he46OwwHzxGROCcdOARcSVR2bIdf8Q4myfLhd
# S9gtB5CRG1FSVpaFwCE0VrEisfDPuh3PYhyArEgCrjzmNu+/+CKaHfIedGwMoYIC
# KDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQQITMwAAAFnWc81RjvAixQAAAAAAWTAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTQwNzI4MDgwMjE2
# WjAjBgkqhkiG9w0BCQQxFgQUfVksfxmwcov2JdebD2LKzaVfqCEwDQYJKoZIhvcN
# AQEFBQAEggEAbta4RoVQrJjFcOlXTCRvaJEeP/Si9jEZKEWQhajtaDJEW8O6meNt
# qk3LmZ+14ZLz8/u5jVCzl9cvwubr2S50tTDgW9I0LwJ3t6KyrJRtNYZBayX4Bs/j
# +z/cuNPXfJgYkPyX+FgioRvEX7kh+tzT7iYqdOVrZURA44cnX/VphILjgE0trW2S
# rihIFHP+f3XUVktcmAKIOcA79Zxdq2SQID7e8cH/iN2Ip2saB/y510JnLuYGGAMd
# 5XWeBVmJ17hH4H/+cr/XgoKEZCpc2h433pIWcABKIFL2t7wMS8OZ7ykR3vdQjFhH
# dl7ST6vv/evqyRUSTcoLeScmFhj47h6nUg==
# SIG # End signature block
