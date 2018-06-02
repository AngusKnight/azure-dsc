Configuration CreateDomainController
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
    Import-DscResource -ModuleName xPendingReboot
    
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
        
        xADDomainController CreateDomainController
        {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $AdminCredential
            SafemodeAdministratorPassword = $SafeModeCredential
            DependsOn                     = @('[WindowsFeatureSet]WindowsFeatures')
        }        
        
        xPendingReboot RebootAfterPromotion
        {
            Name      = 'RebootAfterPromotion'
            DependsOn = @('[xADDomainController]CreateDomainController')
        }
    }
}