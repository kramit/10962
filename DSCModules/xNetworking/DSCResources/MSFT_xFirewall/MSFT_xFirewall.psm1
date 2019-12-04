# Default Display Group for the Firewall cmdlets
$DefaultDisplayGroup = "DSC_FirewallRule"

# DSC uses the Get-TargetResource cmdlet to fetch the status of the resource instance specified in the parameters for the target machine
function Get-TargetResource 
{    
    param 
    (        
        # Name of the Firewall Rule
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        # Localized, user-facing name of the Firewall Rule being created        
        [ValidateNotNullOrEmpty()]
        [String]$DisplayName = $Name,
        
        # Name of the Firewall Group where we want to put the Firewall Rules
        [ValidateNotNullOrEmpty()]
        [String]$DisplayGroup = $DefaultDisplayGroup,

        # Ensure the presence/absence of the resource
        [ValidateSet("Present", "Absent")]
        [String]$Ensure,

        # Permit or Block the supplied configuration 
        [Parameter(Mandatory)]
        [ValidateSet("NotConfigured", "Allow", "Block")]
        [String]$Access,

        # Enable or disable the supplied configuration        
        [ValidateSet("Enabled", "Disabled")]
        [String]$State,

        # Specifies one or more profiles to which the rule is assigned        
        [ValidateSet("Any", "Public", "Private", "Domain")]
        [String[]]$Profile,

        # Direction of the connection        
        [ValidateSet("Inbound", "Outbound")]
        [String]$Direction,

        # Specific Port used for filter. Specified by port number, range, or keyword        
        [ValidateNotNullOrEmpty()]
        [String[]]$RemotePort,

        # Local Port used for the filter        
        [ValidateNotNullOrEmpty()]
        [String[]]$LocalPort,

        # Specific Protocol for filter. Specified by name, number, or range        
        [ValidateNotNullOrEmpty()]
        [String]$Protocol,

        # Documentation for the Rule       
        [String]$Description,

        # Path and file name of the program for which the rule is applied        
        [ValidateNotNullOrEmpty()]
        [String]$ApplicationPath,

        # Specifies the short name of a Windows service to which the firewall rule applies        
        [ValidateNotNullOrEmpty()]
        [String]$Service
    )

    # Hash table for Get
    $getTargetResourceResult = @{}

    Write-Verbose "GET: Get Generic Settings for Firewall"
    $getTargetResourceResult.FirewallSettings = Get-NetFirewallSetting -All

    Write-Verbose "GET: Get Rules for the specified Name[$Name] and DisplayGroup[$DisplayGroup]"
    $firewallRules = Get-FirewallRules -Name $Name -DisplayGroup $DisplayGroup

    if ($firewallRules.Count -eq 0)
    {        
        Write-Verbose "GET: Firewall Rule does not exist, there is nothing interesting to do"

        $getTargetResourceResult.Ensure = ($Ensure -eq "Absent")

        return $getTargetResourceResult
    }

    $getTargetResourceResult.Ensure = ($Ensure -eq "Present")

    foreach ($firewallRule in $firewallRules)
    {
        $firewallRuleMap = Get-FirewallRuleProperty -FirewallRule $firewallRule -Property All
        $firewallRuleMap.Rule = $firewallRule

        Write-Verbose "GET: Validate each defined parameter against the existing Firewall Rule [$Name]"
        if (Test-RuleHasProperties  -FirewallRule $firewallRule `
                                    -Name $Name `
                                    -DisplayGroup $DisplayGroup `
                                    -State $State `
                                    -Profile $Profile `
                                    -Direction $Direction `
                                    -Access $Access `
                                    -RemotePort $RemotePort `
                                    -LocalPort $LocalPort `
                                    -Protocol $Protocol `
                                    -Description $Description `
                                    -ApplicationPath $ApplicationPath `
                                    -Service $Service
        )
        {
            Write-Verbose "GET: Add rule[$Name] to return object"
            $getTargetResourceResult[$firewallRule.Name] += @($firewallRuleMap)
        }
    }

    return $getTargetResourceResult;
}

# DSC uses Set-TargetResource cmdlet to create, delete or configure the resource instance on the target machine
function Set-TargetResource 
{   
    param 
    (        
        # Name of the Firewall Rule
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        # Localized, user-facing name of the Firewall Rule being created        
        [ValidateNotNullOrEmpty()]
        [String]$DisplayName = $Name,
        
        # Name of the Firewall Group where we want to put the Firewall Rules        
        [ValidateNotNullOrEmpty()]
        [String]$DisplayGroup = $DefaultDisplayGroup,

        # Ensure the presence/absence of the resource
        [ValidateSet("Present", "Absent")]
        [String]$Ensure = "Present",

        # Permit or Block the supplied configuration 
        [Parameter(Mandatory)]
        [ValidateSet("NotConfigured", "Allow", "Block")]
        [String]$Access = "Allow",

        # Enable or disable the supplied configuration        
        [ValidateSet("Enabled", "Disabled")]
        [String]$State = "Enabled",

        # Specifies one or more profiles to which the rule is assigned        
        [ValidateSet("Any", "Public", "Private", "Domain")]
        [String[]]$Profile = ("Any"),

        # Direction of the connection        
        [ValidateSet("Inbound", "Outbound")]
        [String]$Direction,

        # Specific Port used for filter. Specified by port number, range, or keyword        
        [ValidateNotNullOrEmpty()]
        [String[]]$RemotePort,

        # Local Port used for the filter        
        [ValidateNotNullOrEmpty()]
        [String[]]$LocalPort,

        # Specific Protocol for filter. Specified by name, number, or range        
        [ValidateNotNullOrEmpty()]
        [String]$Protocol,

        # Documentation for the Rule       
        [String]$Description,

        # Path and file name of the program for which the rule is applied        
        [ValidateNotNullOrEmpty()]
        [String]$ApplicationPath,

        # Specifies the short name of a Windows service to which the firewall rule applies        
        [ValidateNotNullOrEmpty()]
        [String]$Service
    )
    
    Write-Verbose "SET: Find firewall rules with specified parameters for Name = $Name, DisplayGroup = $DisplayGroup"
    $firewallRules = Get-FirewallRules -Name $Name -DisplayGroup $DisplayGroup                                   
    
    $exists = ($firewallRules -ne $null)       
    
    if ($Ensure -eq "Present")
    {        
        Write-Verbose "SET: We want the firewall rule to exist since Ensure is set to $Ensure"
        if ($exists)
        {
            Write-Verbose "SET: We want the firewall rule to exist and it does exist. Check for valid properties"
            foreach ($firewallRule in $firewallRules)
            {
                Write-Verbose "SET: Check each defined parameter against the existing firewall rule - $($firewallRule.Name)"
                if (Test-RuleHasProperties -FirewallRule $firewallRule `
                                           -Name $Name `
                                           -DisplayGroup $DisplayGroup `
                                           -State $State `
                                           -Profile $Profile `
                                           -Direction $Direction `
                                           -Access $Access `
                                           -RemotePort $RemotePort `
                                           -LocalPort $LocalPort `
                                           -Protocol $Protocol `
                                           -Description $Description `
                                           -ApplicationPath $ApplicationPath `
                                           -Service $Service
                )
                {
                }
                else
                {
                    
                    Write-Verbose "SET: Removing existing firewall rule [$Name] to recreate one based on desired configuration"
                    Remove-NetFirewallRule -Name $Name

                    # Set the Firewall rule based on specified parameters
                    Set-FirewallRule    -Name $Name `
                                        -DisplayName $DisplayName `
                                        -DisplayGroup $DisplayGroup `
                                        -State $State `
                                        -Profile $Profile `
                                        -Direction $Direction `
                                        -Access $Access `
                                        -RemotePort $RemotePort `
                                        -LocalPort $LocalPort `
                                        -Protocol $Protocol `
                                        -Description $Description `
                                        -ApplicationPath $ApplicationPath `
                                        -Service $Service -Verbose
                }
            }        
        }        
        else
        {
            Write-Verbose "SET: We want the firewall rule [$Name] to exist, but it does not"

            # Set the Firewall rule based on specified parameters
            Set-FirewallRule    -Name $Name `
                                -DisplayName $DisplayName `
                                -DisplayGroup $DisplayGroup `
                                -State $State `
                                -Profile $Profile `
                                -Direction $Direction `
                                -Access $Access `
                                -RemotePort $RemotePort `
                                -LocalPort $LocalPort `
                                -Protocol $Protocol `
                                -Description $Description `
                                -ApplicationPath $ApplicationPath `
                                -Service $Service -Verbose
        }
    }    
    elseif ($Ensure -eq "Absent")
    {
        Write-Verbose "SET: We do not want the firewall rule to exist"        
        if ($exists)
        {
            Write-Verbose "SET: We do not want the firewall rule to exist, but it does. Removing the Rule(s)"
            foreach ($firewallRule in $firewallRules)
            {
                Remove-NetFirewallRule -Name $firewallRule.Name
            }
        }        
        else
        {
            Write-Verbose "SET: We do not want the firewall rule to exist, and it does not"
            # Do Nothing
        }           
    }
}

# DSC uses Test-TargetResource cmdlet to check the status of the resource instance on the target machine
function Test-TargetResource 
{ 
    param 
    (        
        # Name of the Firewall Rule
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        # Localized, user-facing name of the Firewall Rule being created        
        [ValidateNotNullOrEmpty()]
        [String]$DisplayName = $Name,
        
        # Name of the Firewall Group where we want to put the Firewall Rules        
        [ValidateNotNullOrEmpty()]
        [String]$DisplayGroup,

        # Ensure the presence/absence of the resource
        [ValidateSet("Present", "Absent")]
        [String]$Ensure = "Present",

        # Permit or Block the supplied configuration 
        [Parameter(Mandatory)]
        [ValidateSet("NotConfigured", "Allow", "Block")]
        [String]$Access,

        # Enable or disable the supplied configuration        
        [ValidateSet("Enabled", "Disabled")]
        [String]$State,

        # Specifies one or more profiles to which the rule is assigned        
        [ValidateSet("Any", "Public", "Private", "Domain")]
        [String[]]$Profile,

        # Direction of the connection        
        [ValidateSet("Inbound", "Outbound")]
        [String]$Direction,

        # Specific Port used for filter. Specified by port number, range, or keyword        
        [ValidateNotNullOrEmpty()]
        [String[]]$RemotePort,

        # Local Port used for the filter        
        [ValidateNotNullOrEmpty()]
        [String[]]$LocalPort,

        # Specific Protocol for filter. Specified by name, number, or range        
        [ValidateNotNullOrEmpty()]
        [String]$Protocol,

        # Documentation for the Rule        
        [String]$Description,

        # Path and file name of the program for which the rule is applied        
        [ValidateNotNullOrEmpty()]
        [String]$ApplicationPath,

        # Specifies the short name of a Windows service to which the firewall rule applies        
        [ValidateNotNullOrEmpty()]
        [String]$Service
    )
    
    Write-Verbose "TEST: Find rules with specified parameters"
    $firewallRules = Get-FirewallRules -Name $Name -DisplayGroup $DisplayGroup
    
    if (!$firewallRules)
    {
        Write-Verbose "TEST: Get-FirewallRules returned NULL"
        
        # Returns whether complies with $Ensure
        $returnValue = ($false -eq ($Ensure -eq "Present"))

        Write-Verbose "TEST: Returning $returnValue"
        
        return $returnValue
    }

    $exists = $true
    $valid = $true
    foreach ($firewallRule in $firewallRules)
    {
        Write-Verbose "TEST: Check each defined parameter against the existing Firewall Rule - $($firewallRule.Name)"
        if (Test-RuleHasProperties  -FirewallRule $firewallRule `
                                    -Name $Name `
                                    -DisplayGroup $DisplayGroup `
                                    -State $State `
                                    -Profile $Profile `
                                    -Direction $Direction `
                                    -Access $Access `
                                    -RemotePort $RemotePort `
                                    -LocalPort $LocalPort `
                                    -Protocol $Protocol `
                                    -Description $Description `
                                    -ApplicationPath $ApplicationPath `
                                    -Service $Service
        )
        {
        }
        else
        {
            $valid = $false
        }
    }

    # Returns whether or not $exists complies with $Ensure
    $returnValue = ($valid -and $exists -eq ($Ensure -eq "Present"))

    Write-Verbose "TEST: Returning $returnValue"
    
    return $returnValue
} 

#region HelperFunctions

######################
## Helper Functions ##
######################

# Function to Set a Firewall Rule based on specified parameters
function Set-FirewallRule
{
    param (
        [Parameter(Mandatory)]
        [String]$Name,
        [String]$DisplayName,
        [String]$DisplayGroup,
        [String]$State,
        [String[]]$Profile,
        [String]$Direction,
        [String]$Access,
        [String[]]$RemotePort,
        [String[]]$LocalPort,
        [String]$Protocol,
        [String]$Description,
        [String]$ApplicationPath,
        [String]$Service
    )

    $parameters = @{}
    $commandName = "New-NetFirewallRule"

    $parameters["Name"] = $Name

    if($DisplayName)
    {
        $parameters["DisplayName"] = $DisplayName
    }

    if($DisplayGroup)
    {
        $parameters["Group"] = $DisplayGroup
    }
    else
    {
        $parameters["Group"] = $DefaultGroup
    }

    if($State)
    {
        if($State -eq "Enabled")
        {
            $parameters["Enabled"] = "True"
        }
        else
        {
            $parameters["Enabled"] = "False"
        }
    }

    if($Profile)
    {
        $parameters["Profile"] = $Profile
    }

    if($Direction)
    {
        $parameters["Direction"] = $Direction
    }

    if($Access)
    {
        $parameters["Action"] = $Access
    }

    if($RemotePort)
    {
        $parameters["RemotePort"] = $RemotePort
    }

    if($LocalPort)
    {
        $parameters["LocalPort"] = $LocalPort
    }

    if($Protocol)
    {
        $parameters["Protocol"] = $Protocol
    }

    if($Description)
    {
        $parameters["Description"] = $Description
    }

    if($ApplicationPath)
    {
        $parameters["Program"] = $ApplicationPath
    }

    if($Service)
    {
        $parameters["Service"] = $Service
    }

    Write-Verbose "SET: Invoke Set-NetFirewallRule [$Name] with splatting its parameters"
    & $commandName @parameters
}

# Function to validate if the supplied Rule adheres to all parameters set
function Test-RuleHasProperties
{
    param (
        [Parameter(Mandatory)]
        $FirewallRule,        
        [String]$Name,
        [String]$DisplayGroup,
        [String]$State,
        [String[]]$Profile,
        [String]$Direction,
        [String]$Access,
        [String[]]$RemotePort,
        [String[]]$LocalPort,
        [String]$Protocol,
        [String]$Description,
        [String]$ApplicationPath,
        [String]$Service
    )

    $properties = Get-FirewallRuleProperty -FirewallRule $FirewallRule -Property All
       
    $desiredConfigurationMatch = $true

    if ($Name -and ($FirewallRule.Name -ne $Name))
    {
        Write-Verbose "Test-RuleHasProperties: Name property value - $FirewallRule.Name does not match desired state - $Name"

        $desiredConfigurationMatch = $false
    }

    if ($Access -and ($FirewallRule.Action -ne $Access))
    {
        Write-Verbose "Test-RuleHasProperties: Access property value - $($FirewallRule.Action) does not match desired state - $Access"

        $desiredConfigurationMatch = $false
    }

    if ($State -and ($FirewallRule.Enabled.ToString() -eq ("Enabled" -ne $State)))
    {
        Write-Verbose "Test-RuleHasProperties: State property value - $FirewallRule.Enabled.ToString() does not match desired state - $State"

        $desiredConfigurationMatch = $false
    }

    if ($Profile)
    {
        [String[]]$networkProfileinRule = $FirewallRule.Profile.ToString() -replace(" ", "") -split(",")

        if ($networkProfileinRule.Count -eq $Profile.Count)
        {
            foreach($networkProfile in $Profile)
            {
                if (-not ($networkProfileinRule -contains($networkProfile)))
                {
                    Write-Verbose "Test-RuleHasProperties: Profile property value - '$networkProfileinRule' does not match desired state - '$Profile'"
        
                    $desiredConfigurationMatch = $false                           
                }
            }
        }
        else
        {
            Write-Verbose "Test-RuleHasProperties: Profile property value - '$networkProfileinRule' does not match desired state - '$Profile'"
            
            $desiredConfigurationMatch = $false  
        }             
    }

    if ($Direction -and ($FirewallRule.Direction -ne $Direction))
    {
        Write-Verbose "Test-RuleHasProperties: Direction property value - $FirewallRule.Direction does not match desired state - $Direction"
        
        $desiredConfigurationMatch = $false

    }

    if ($RemotePort)
    {
        [String[]]$remotePortInRule = $properties.PortFilters.RemotePort
     
        if ($remotePortInRule.Count -eq $RemotePort.Count)
        {
            foreach($port in $RemotePort)
            {
                if (-not ($remotePortInRule -contains($port)))
                {
                    Write-Verbose "Test-RuleHasProperties: RemotePort property value - '$remotePortInRule' does not match desired state - '$RemotePort'"
                    
                    $desiredConfigurationMatch = $false                   
                }
            }
        }
        else
        {
            Write-Verbose "Test-RuleHasProperties: RemotePort property value - '$remotePortInRule' does not match desired state - '$RemotePort'"

            $desiredConfigurationMatch = $false
        } 
    }

    if ($LocalPort)
    {
        [String[]]$localPortInRule = $properties.PortFilters.LocalPort
     
        if ($localPortInRule.Count -eq $LocalPort.Count)
        {
            foreach($port in $LocalPort)
            {
                if (-not ($localPortInRule -contains($port)))
                {
                    Write-Verbose "Test-RuleHasProperties: LocalPort property value - '$localPortInRule' does not match desired state - '$LocalPort'"

                    $desiredConfigurationMatch = $false                 
                }
            }
        }
        else
        {
            Write-Verbose "Test-RuleHasProperties: LocalPort property value - '$localPortInRule' does not match desired state - '$LocalPort'"

            $desiredConfigurationMatch = $false
        } 
    }

    if ($Protocol -and ($properties.PortFilters.Protocol -ne $Protocol)) 
    {
        Write-Verbose "Test-RuleHasProperties: Protocol property value - $properties.PortFilters.Protocol does not match desired state - $Protocol"

        $desiredConfigurationMatch = $false
    }

    if ($Description -and ($FirewallRule.Description -ne $Description)) 
    {
        Write-Verbose "Test-RuleHasProperties: Description property value - $FirewallRule.Description does not match desired state - $Description"

        $desiredConfigurationMatch = $false
    }

    if ($ApplicationPath -and ($properties.ApplicationFilters.Program -ne $ApplicationPath)) 
    {
        Write-Verbose "Test-RuleHasProperties: ApplicationPath property value - $properties.ApplicationFilters.Program does not match desired state - $ApplicationPath"

        $desiredConfigurationMatch = $false
    }

    if ($Service -and ($properties.ServiceFilters.Service -ne $Service)) 
    {
        Write-Verbose "Test-RuleHasProperties: Service property value - $properties.ServiceFilters.Service  does not match desired state - $Service"

        $desiredConfigurationMatch = $false
    }

    Write-Verbose "Test-RuleHasProperties returning $desiredConfigurationMatch"
    return $desiredConfigurationMatch
}

# Returns a list of FirewallRules that comply to the specified parameters.
function Get-FirewallRules
{
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        [String]$DisplayGroup
    )

    $firewallRules = @(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue)

    if (-not $firewallRules)
    {
        Write-Verbose "Get-FirewallRules: No Firewall Rules found for [$Name]"
        return $null
    }
    else
    {
        if ($DisplayGroup)
        {        
            foreach ($firewallRule in $firewallRules)
            {
                if ($firewallRule.DisplayGroup -eq $DisplayGroup)
                {
                    Write-Verbose "Get-FirewallRules: Found a Firewall Rule for Name: [$Name] and DisplayGroup [$DisplayGroup]"
                    return $firewallRule
                }
            }
        }
    }
        
    return $firewallRules    
}

# Returns the filters associated with the given firewall rule
function Get-FirewallRuleProperty
{

    param ( 
        [Parameter(Mandatory)]
        $FirewallRule,
        
        [Parameter(Mandatory)]
        [ValidateSet("All", "AddressFilter", "ApplicationFilter", "InterfaceFilter",
        "InterfaceTypeFilter", "PortFilter", "Profile", "SecurityFilter", "ServiceFilter")]
        $Property
     )
    
    if ($Property -eq "All")
    {
        Write-Verbose "Get-FirewallRuleProperty:  Get all the properties"

        $properties = @{}

        Write-Verbose "Get-FirewallRuleProperty: Add filter info to rule map"
        $properties.AddressFilters =  @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $FirewallRule)
        $properties.ApplicationFilters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $FirewallRule)
        $properties.InterfaceFilters = @(Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $FirewallRule)
        $properties.InterfaceTypeFilters = @(Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $FirewallRule)
        $properties.PortFilters = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $FirewallRule)
        $properties.Profile = @(Get-NetFirewallProfile -AssociatedNetFirewallRule $FirewallRule)
        $properties.SecurityFilters = @(Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $FirewallRule)
        $properties.ServiceFilters = @(Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $FirewallRule)
    
        return $properties
    }        

    if ($Property -eq "AddressFilter" -or $Property -eq "ApplicationFilter" -or $Property -eq "InterfaceFilter" `
        -or $Property -eq "InterfaceTypeFilter" -or $Property -eq "PortFilter" -or $Property -eq "Profile" `
        -or $Property -eq "SecurityFilter" -or $Property -eq "ServiceFilter")
    {
        Write-Verbose "Get-FirewallRuleProperty: Get only [$Property] property"

        return &(Get-Command "Get-NetFirewall$Property")  -AssociatedNetFireWallRule $FireWallRule
    }    
}

#endregion

Export-ModuleMember -Function *-TargetResource















# SIG # Begin signature block
# MIIatQYJKoZIhvcNAQcCoIIapjCCGqICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUIaHjeTVU/Xm4pL1K5WY77HCe
# q1igghV6MIIEuzCCA6OgAwIBAgITMwAAAFrtL/TkIJk/OgAAAAAAWjANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTQwNTIzMTcxMzE1
# WhcNMTUwODIzMTcxMzE1WjCBqzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# DTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpCOEVDLTMw
# QTQtNzE0NDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALMhIt9q0L/7KcnVbHqJqY0T
# vJS16X0pZdp/9B+rDHlhZlRhlgfw1GBLMZsJr30obdCle4dfdqHSxinHljqjXxeM
# duC3lgcPx2JhtLaq9kYUKQMuJrAdSgjgfdNcMBKmm/a5Dj1TFmmdu2UnQsHoMjUO
# 9yn/3lsgTLsvaIQkD6uRxPPOKl5YRu2pRbRptlQmkRJi/W8O5M/53D/aKWkfSq7u
# wIJC64Jz6VFTEb/dqx1vsgpQeAuD7xsIsxtnb9MFfaEJn8J3iKCjWMFP/2fz3uzH
# 9TPcikUOlkYUKIccYLf1qlpATHC1acBGyNTo4sWQ3gtlNdRUgNLpnSBWr9TfzbkC
# AwEAAaOCAQkwggEFMB0GA1UdDgQWBBS+Z+AuAhuvCnINOh1/jJ1rImYR9zAfBgNV
# HSMEGDAWgBQjNPjZUkZwCu1A+3b7syuwwzWzDzBUBgNVHR8ETTBLMEmgR6BFhkNo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNyb3Nv
# ZnRUaW1lU3RhbXBQQ0EuY3JsMFgGCCsGAQUFBwEBBEwwSjBIBggrBgEFBQcwAoY8
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3NvZnRUaW1l
# U3RhbXBQQ0EuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBBQUA
# A4IBAQAgU4KQrqZNTn4zScizrcTDfhXQEvIPJ4p/W78+VOpB6VQDKym63VSIu7n3
# 2c5T7RAWPclGcLQA0fI0XaejIiyqIuFrob8PDYfQHgIb73i2iSDQLKsLdDguphD/
# 2pGrLEA8JhWqrN7Cz0qTA81r4qSymRpdR0Tx3IIf5ki0pmmZwS7phyPqCNJp5mLf
# cfHrI78hZfmkV8STLdsWeBWqPqLkhfwXvsBPFduq8Ki6ESus+is1Fm5bc/4w0Pur
# k6DezULaNj+R9+A3jNkHrTsnu/9UIHfG/RHpGuZpsjMnqwWuWI+mqX9dEhFoDCyj
# MRYNviGrnPCuGnxA1daDFhXYKPvlMIIE7DCCA9SgAwIBAgITMwAAAMps1TISNcTh
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
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRoDzi2yPnQKg52
# tIHvZd4sgY6tNDBeBgorBgEEAYI3AgEMMVAwTqAmgCQATQBpAGMAcgBvAHMAbwBm
# AHQAIABMAGUAYQByAG4AaQBuAGehJIAiaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L2xlYXJuaW5nIDANBgkqhkiG9w0BAQEFAASCAQByV6OLgRSWX/kcvv4pCkn279vc
# n9JyALLzIi7SdgLSksrZ6mpSrXojf75g3qExG3gpb/c+aSvvBz9u/xn9NjqSLuK8
# esXAjaisySojbAyb2FGyuyOh1x2D44dpyS20ctr/iq4Mwdj1iLnSj1zm5TSPACA/
# yOzYNXnw98GWZFZvoTxnpYtgyo+3AYwhxKrIuHOkjnmexXU/pXVkDXBEPV5XyYUj
# uXFTnVB0xOYK9vouL6d/fyLkSqGxKuUEiCbgWHURbtlzfEWYxTVYNpgCwZfmR6Ty
# mUn0Rbzv7VRJhKrCvkWmPN1PUDIhmyKQ4wA5ICue6OAQSszmfun7DoxBmK4PoYIC
# KDCCAiQGCSqGSIb3DQEJBjGCAhUwggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQQITMwAAAFrtL/TkIJk/OgAAAAAAWjAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTQwNzI4MDgwMjE2
# WjAjBgkqhkiG9w0BCQQxFgQU86I1DZPonULBhGjWIIKS5WoTwB8wDQYJKoZIhvcN
# AQEFBQAEggEAgYZdf+aT1LvT90v2GPzceYIQfude32aUTzEu/S20WPORv6cLAUqd
# kYXkORjlPHNbnUGDUkV9qgQwt8e0sBgBppTxQPf6VeDY8TGYd7sAWEb9Ld0kQe8D
# ZqARIEyXMoOxmm6BsMPgUqtFNKAoglxg/RCrg9CzfdQDS4OBKjKlFLIBlA8ct7DV
# zRv9aLYpagpZfGDqciA+VMH/dJ4Ykrd3R++wCh/Z07wlvZf+00Ve/UefrOwRRjnA
# ulrj6HbzF8dpkYbilKBjorIVBnO9uavncWpXL4d+aKHaAnNhRRVE9wQH1xSJfJbj
# 6YzMpB+bb5sJTYVzo5qOqJO7vmF5n41Jxw==
# SIG # End signature block
