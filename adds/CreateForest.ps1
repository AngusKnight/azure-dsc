Configuration CreateForest
{
   param
   (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCredential,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SafeModeCredential,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xNetworking

    $InterfaceAlias = (Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1).Name
    $WindowsFeatures = @('DNS','AD-Domain-Services')

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }
        
        WindowsFeatureSet WindowsFeatures
        {
            Ensure               = 'Present'
            Name                 = $WindowsFeatures
            IncludeAllSubFeature = $false
        }
        
        xDnsServerAddress DnsServerAddress
        {
            Address        = '127.0.0.1'
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn      = @('[WindowsFeatureSet]WindowsFeatures')
        }
        
        xADDomain AddDomain
        {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $AdminCredential
            SafemodeAdministratorPassword = $SafeModeCredential
            DependsOn                     = @('[xDnsServerAddress]DnsServerAddress')
        }
    }
}