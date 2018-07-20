configuration CreateFailoverCluster
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$DomainAdmin,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SqlServiceAccount,

        [Parameter(Mandatory)]
        [String]$ClusterName,

        [Parameter(Mandatory)]
        [String]$ClusterOwnerNode,

        [Parameter(Mandatory)]
        [String]$WitnessStorageBlobEndpoint,

        [Parameter(Mandatory)]
        [String]$WitnessStorageAccountKey,

        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnAvailabilityGroupName,

        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnAvailabilityGroupIpAddress

    )

    Import-DscResource -ModuleName ComputerManagementDsc,NetworkingDsc,PSDesiredStateConfiguration,SqlServerDsc,xFailOverCluster

    [String]$DomainNetbiosName=(Get-NetBIOSName -DomainName $DomainName)
    [System.Management.Automation.PSCredential]$DomainAdmin = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($DomainAdmin.UserName)", $DomainAdmin.Password)
    $SqlServiceAccount = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SqlServiceAccount.UserName)", $SqlServiceAccount.Password)
    $ComputerName = $env:COMPUTERNAME
    $WindowsFeatures = @('Failover-Clustering','RSAT-Clustering-Mgmt','RSAT-Clustering-PowerShell','RSAT-Clustering-CmdInterface','RSAT-AD-PowerShell','RSAT-ADDS-Tools')
    $SqlInstanceName = 'MSSQLSERVER'
    $ClusterService = 'NT SERVICE\ClusSvc'
    $DatabaseMirroringPort = 5022
    $ListenerPort = 59999
    $ipcomponents = $SqlAlwaysOnAvailabilityGroupIpAddress.Split('.')
    $ipcomponents[3] = [convert]::ToString(([convert]::ToInt32($ipcomponents[3])) -1)
    $ClusterIp = $ipcomponents -join '.'
    $SqlAlwaysOnAvailabilityGroupListenerName = '{0}Listener' -f $SqlAlwaysOnAvailabilityGroupName

    $suri = [System.uri]$witnessStorageBlobEndpoint
    $uricomp = $suri.Host.split('.')
    $witnessStorageAccount = $uriComp[0]
    $witnessEndpoint = $uricomp[-3] + '.' + $uricomp[-2] + '.' + $uricomp[-1]

    WaitForSqlSetup

    Node localhost
    {
        WindowsFeatureSet WindowsFeatures
        {
            Ensure               = 'Present'
            Name                 = $WindowsFeatures
            IncludeAllSubFeature = $false
        }

        Firewall DatabaseMirroringFirewallRule
        {
            Ensure      = 'Present'
            Action      = 'Allow'
            Direction   = 'Inbound'
            Name        = 'SQL-Server-Database-Mirroring-TCP-In'
            DisplayName = 'SQL Server Database Mirroring (TCP-In)'
            Description = 'Inbound rule for SQL Server to allow TCP traffic for the Database Mirroring.'
            Group       = 'SQL Server'
            Enabled     = 'True'
            Protocol    = 'TCP'
            LocalPort   = $DatabaseMirroringPort -as [string]
        }

        Firewall ListenerFirewallRule
        {
            Ensure      = 'Present'
            Action      = 'Allow'
            Direction   = 'Inbound'
            Name        = 'SQL-Server-Availability-Group-Listener-TCP-In'
            DisplayName = 'SQL Server Availability Group Listener (TCP-In)'
            Description = 'Inbound rule for SQL Server to allow TCP traffic for the Availability Group listener.'
            Group       = 'SQL Server'
            Enabled     = 'True'
            Protocol    = 'TCP'
            LocalPort   = $ListenerPort -as [string]
        }

        SqlServerLogin AddClusterSvcAccountToSqlServer
        {
            Ensure               = 'Present'
            Name                 = $ClusterService
            LoginType            = 'WindowsUser'
            ServerName           = $env:COMPUTERNAME
            InstanceName         = $SqlInstanceName
            PsDscRunAsCredential = $DomainAdmin
        }

        SqlServerPermission AssignClusterSvcPermissions
        {
            Ensure               = 'Present'
            InstanceName         = $SqlInstanceName
            Principal            = $ClusterService
            Permission           = @('ConnectSql','AlterAnyAvailabilityGroup','ViewServerState')
            DependsOn            = @('[SqlServerLogin]AddClusterSvcAccountToSqlServer')
            PsDscRunAsCredential = $DomainAdmin
        }

        Script ResetSpns
        {
            GetScript = {
                return @{ 'Result' = $true }
            }

            SetScript = {
                $SpnList = @(
                    ('MSSQLSvc/{0}.{1}' -f $using:ComputerName, $using:DomainName),
                    ('MSSQLSvc/{0}.{1}:1433' -f $using:ComputerName, $using:DomainName)
                )
                foreach ($spn in $SpnList)
                {
                    $cmd = 'setspn -D {0} {1}' -f $spn, $using:ComputerName
                    Write-Verbose $cmd
                    Invoke-Expression $cmd

                    $cmd = 'setspn -A {0} {1}' -f $spn, $using:SqlServiceAccount.UserName
                    Write-Verbose $cmd
                    Invoke-Expression $cmd
                }
            }

            TestScript = {
                $false
            }

            PsDscRunAsCredential = $DomainAdmin
        }

        if ($ClusterOwnerNode -eq $env:COMPUTERNAME) # This is the primary
        {
            Script PrestageCNO
            {
                GetScript = {
                    return @{ 'Result' = $true }
                }

                SetScript = {
                    $dn = (Get-ADComputer -Identity $using:ComputerName).DistinguishedName
                    $ou = $dn.Substring($dn.IndexOf('OU='))
                    New-ADComputer -Name $using:ClusterName -Enabled $false -Path $ou -Verbose
                }

                TestScript = {
                    try
                    {
                        $computer = Get-ADComputer -Identity $using:ClusterName
                    }
                    catch {}
                    $computer -ne $null
                }

                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[WindowsFeatureSet]WindowsFeatures')
            }

            Script SetCNOPermissions
            {
                GetScript = {
                    return @{ 'Result' = $true }
                }

                SetScript = {
                    $dn = (Get-ADComputer -Identity $using:ComputerName).DistinguishedName
                    $ou = $dn.Substring($dn.IndexOf('OU='))
                    $user = '{0}\{1}' -f $using:DomainNetbiosName, $using:ClusterName
                    $PermsList = @('GR','CC;computer')
                    foreach ($permission in $PermsList)
                    {
                        $cmd = 'dsacls.exe {0} /I:T /G "{1}:{2}"' -f $ou, $user, $permission
                        Write-Verbose $cmd
                        Invoke-Expression $cmd
                    }
                }

                TestScript = {
                    $false
                }

                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[Script]PrestageCNO')
            }

            xCluster CreateCluster
            {
                Name                          = $ClusterName
                StaticIPAddress               = $ClusterIp
                DomainAdministratorCredential = $DomainAdmin
                DependsOn                     = @('[Script]SetCNOPermissions','[Script]ResetSpns')
            }

            Script SetCloudWitness
            {
                GetScript = {
                    return @{ 'Result' = $true }
                }

                SetScript = {
                    Set-ClusterQuorum -CloudWitness -AccountName $using:witnessStorageAccount -AccessKey $using:witnessStorageAccountKey -Endpoint $using:witnessEndpoint
                }

                TestScript = {
                    $(Get-ClusterQuorum).QuorumResource.ResourceType -eq 'Cloud Witness'
                }

                PsDscRunAsCredential = $DomainAdmin
                DependsOn = @('[xCluster]CreateCluster')
            }

            SqlAlwaysOnService EnableAlwaysOn
            {
                Ensure               = 'Present'
                ServerName           = $env:COMPUTERNAME
                InstanceName         = $SqlInstanceName
                RestartTimeout       = 120
                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[xCluster]CreateCluster')
            }

            # Create a DatabaseMirroring endpoint
            SqlServerEndpoint HADREndpoint
            {
                EndPointName         = 'HADR'
                Ensure               = 'Present'
                Port                 = $DatabaseMirroringPort
                ServerName           = $env:COMPUTERNAME
                InstanceName         = $SqlInstanceName
                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[SqlAlwaysOnService]EnableAlwaysOn')
            }

            # Create the availability group on the instance tagged as the primary replica
            SqlAG CreateAG
            {
                Ensure               = 'Present'
                Name                 = $SqlAlwaysOnAvailabilityGroupName
                ServerName           = $env:COMPUTERNAME
                InstanceName         = $SqlInstanceName
                AvailabilityMode     = 'SynchronousCommit'
                FailoverMode         = 'Automatic' 
                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[SqlServerEndpoint]HADREndpoint')
            }

            SqlAGListener AvailabilityGroupListener
            {
                Ensure               = 'Present'
                ServerName           = $ClusterOwnerNode
                InstanceName         = $SqlInstanceName
                AvailabilityGroup    = $SqlAlwaysOnAvailabilityGroupName
                Name                 = $SqlAlwaysOnAvailabilityGroupListenerName
                IpAddress            = "$SqlAlwaysOnAvailabilityGroupIpAddress/255.255.255.0"
                Port                 = 1433
                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[SqlAG]CreateAG')
            }

            Script SetProbePort
            {
                GetScript = {
                    return @{ 'Result' = $true }
                }

                SetScript = {
                    $ipResourceName = $using:SqlAlwaysOnAvailabilityGroupName + '_' + $using:SqlAlwaysOnAvailabilityGroupIpAddress
                    $ipResource = Get-ClusterResource $ipResourceName
                    $clusterResource = Get-ClusterResource -Name $using:SqlAlwaysOnAvailabilityGroupName 
                    Set-ClusterParameter -InputObject $ipResource -Name ProbePort -Value $using:ListenerPort
                    Stop-ClusterResource $ipResource
                    Stop-ClusterResource $clusterResource
                    Start-ClusterResource $clusterResource #This should be enough
                    Start-ClusterResource $ipResource #To be on the safe side
                }

                TestScript = {
                    $ipResourceName = $using:SqlAlwaysOnAvailabilityGroupName + '_' + $using:SqlAlwaysOnAvailabilityGroupIpAddress
                    $resource = Get-ClusterResource $ipResourceName
                    $probePort = $(Get-ClusterParameter -InputObject $resource -Name ProbePort).Value
                    Write-Verbose "ProbePort = $probePort"
                    ($(Get-ClusterParameter -InputObject $resource -Name ProbePort).Value -eq $using:ListenerPort)
                }

                PsDscRunAsCredential = $DomainAdmin
                DependsOn = @('[SqlAGListener]AvailabilityGroupListener')
            }
        }
        else
        {
            xWaitForCluster WaitForCluster
            {
                Name             = $ClusterName
                RetryIntervalSec = 10
                RetryCount       = 60
                DependsOn        = @('[WindowsFeatureSet]WindowsFeatures','[Script]ResetSpns')
            }

            #We have to do this manually due to a problem with xCluster:
            #  see: https://github.com/PowerShell/xFailOverCluster/issues/7
            #      - Cluster is added with an IP and the xCluster module tries to access this IP. 
            #      - Cluster is not not yet responding on that address
            Script JoinExistingCluster
            {
                GetScript = {
                    return @{ 'Result' = $true }
                }

                SetScript = {
                    $targetNodeName = $env:COMPUTERNAME
                    Add-ClusterNode -Name $targetNodeName -Cluster $using:ClusterOwnerNode
                }

                TestScript = {
                    $targetNodeName = $env:COMPUTERNAME
                    $(Get-ClusterNode -Cluster $using:ClusterOwnerNode).Name -contains $targetNodeName
                }

                PsDscRunAsCredential = $DomainAdmin
                DependsOn = @('[xWaitForCluster]WaitForCluster')
            }

            SqlAlwaysOnService EnableAlwaysOn
            {
                Ensure               = 'Present'
                ServerName           = $env:COMPUTERNAME
                InstanceName         = $SqlInstanceName
                RestartTimeout       = 120
                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[Script]JoinExistingCluster')
            }

            # Create a DatabaseMirroring endpoint
            SqlServerEndpoint HADREndpoint
            {
                EndPointName         = 'HADR'
                Ensure               = 'Present'
                Port                 = $DatabaseMirroringPort
                ServerName           = $env:COMPUTERNAME
                InstanceName         = $SqlInstanceName
                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[SqlAlwaysOnService]EnableAlwaysOn')
            }

            SqlWaitForAG WaitForAG
            {
                Name                 = $SqlAlwaysOnAvailabilityGroupName
                RetryIntervalSec     = 20
                RetryCount           = 30
                PsDscRunAsCredential = $DomainAdmin
                DependsOn            = @('[SqlServerEndpoint]HADREndpoint')
            }

            # Add the availability group replica to the availability group
            SqlAGReplica AddReplica
            {
                Ensure                     = 'Present'
                Name                       = $env:COMPUTERNAME
                AvailabilityGroupName      = $SqlAlwaysOnAvailabilityGroupName
                ServerName                 = $env:COMPUTERNAME
                InstanceName               = $SqlInstanceName
                PrimaryReplicaServerName   = $ClusterOwnerNode
                PrimaryReplicaInstanceName = $SqlInstanceName
                AvailabilityMode           = 'SynchronousCommit'
                FailoverMode               = 'Automatic'
                PsDscRunAsCredential       = $DomainAdmin
                DependsOn                  = @('[SqlWaitForAG]WaitForAG')
            }
        }

        LocalConfigurationManager 
        {
            RebootNodeIfNeeded = $true
        }

    }

}

function WaitForSqlSetup
{
    # Wait for SQL Server Setup to finish before proceeding.
    while ($true)
    {
        try
        {
            Get-ScheduledTaskInfo "\ConfigureSqlImageTasks\RunConfigureImage" -ErrorAction Stop
            Start-Sleep -Seconds 5
        }
        catch
        {
            break
        }
    }
}

function Get-NetBIOSName
{ 
    [OutputType([string])]
    param
    (
        [string]$DomainName
    )

    if ($DomainName.Contains('.'))
    {
        $length=$DomainName.IndexOf('.')
        if ( $length -ge 16)
        {
            $length=15
        }
        return $DomainName.Substring(0,$length)
    }
    else
    {
        if ($DomainName.Length -gt 15)
        {
            return $DomainName.Substring(0,15)
        }
        else
        {
            return $DomainName
        }
    }
}