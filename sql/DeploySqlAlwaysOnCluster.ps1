Configuration DeploySqlAlwaysOnCluster
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
        [System.Management.Automation.PSCredential]$SqlSa,

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

    Import-DscResource -ModuleName cNtfsAccessControl,ComputerManagementDsc,NetworkingDsc,PSDesiredStateConfiguration,SecurityPolicyDsc,SqlServer,SqlServerDsc,StorageDsc,xActiveDirectory,xFailOverCluster

    $DomainNetbiosName=(Get-NetBIOSName -DomainName $DomainName)
    $DomainAdmin = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($DomainAdmin.UserName)", $DomainAdmin.Password)
    $SqlServiceUserName = $SqlServiceAccount.UserName
    $SqlServiceAccount = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SqlServiceAccount.UserName)", $SqlServiceAccount.Password)
    
    $ComputerName = $env:COMPUTERNAME
    $WindowsFeatures = @('Failover-Clustering','RSAT-Clustering-Mgmt','RSAT-Clustering-PowerShell','RSAT-Clustering-CmdInterface','RSAT-AD-PowerShell','RSAT-ADDS-Tools')
    $ipcomponents = $SqlAlwaysOnAvailabilityGroupIpAddress.Split('.')
    $ipcomponents[3] = [convert]::ToString(([convert]::ToInt32($ipcomponents[3])) -1)
    $ClusterIp = $ipcomponents -join '.'

    $suri = [System.uri]$witnessStorageBlobEndpoint
    $uricomp = $suri.Host.split('.')
    $witnessStorageAccount = $uriComp[0]
    $witnessEndpoint = $uricomp[-3] + '.' + $uricomp[-2] + '.' + $uricomp[-1]

    $DataDiskDriveLetter = Get-DataDisk
    $ClusterService = 'NT SERVICE\ClusSvc'
    $DatabaseMirroringPort = 5022
    $ListenerPort = 59999
    $SqlAlwaysOnAvailabilityGroupListenerName = '{0}Listener' -f $SqlAlwaysOnAvailabilityGroupName
    $SqlBackupDir = "$DataDiskDriveLetter\Backup"
    $SqlDataDir = "$DataDiskDriveLetter\Data"
    $SqlDiskName = 'SqlDisk01'
    $SqlInstanceName = 'MSSQLSERVER'
    $SqlInstanceData = 'MSSQL13.MSSQLSERVER'
    $SqlLogDir = "$DataDiskDriveLetter\Log"
    $SqlPoolName = 'SqlPool01'

    WaitForSqlSetup

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

        Firewall DatabaseEngineFirewallRule
        {
            Ensure      = 'Present'
            Action      = 'Allow'
            Direction   = 'Inbound'
            Name        = 'SQL-Server-Database-Engine-TCP-In'
            DisplayName = 'SQL Server Database Engine (TCP-In)'
            Description = 'Inbound rule for SQL Server to allow TCP traffic for the Database Engine.'
            Group       = 'SQL Server'
            Enabled     = 'True'
            Protocol    = 'TCP'
            LocalPort   = '1433'
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

        xADUser CreateSqlServerServiceAccount
        {
            Ensure                         = 'Present'
            Enabled                       = $true
            DomainAdministratorCredential = $DomainAdmin
            DomainName                    = $DomainName
            UserName                      = $SqlServiceUserName
            Password                      = $SqlServiceAccount
            PasswordNeverExpires          = $true
            DependsOn                     = @('[WindowsFeatureSet]WindowsFeatures')
        }

        UserRightsAssignment AssignLogOnAsServiceRight
        {
            Policy    = 'Log_on_as_a_service'
            Identity  = $SqlServiceAccount.UserName
            DependsOn = @('[xADUser]CreateSqlServerServiceAccount')
        }

        Script UninstallDefaultInstance
        {
            GetScript = {
                @{ Result = $true }
            }

            SetScript = {
                & C:\SQLServerFull\Setup.exe /Action=Uninstall /FEATURES=SQL,AS,IS,RS,DQC /INSTANCENAME=MSSQLSERVER /Q >$null
                if ($LASTEXITCODE -eq 3010 -or $LASTEXITCODE -eq 1641)
                {
                    Write-Verbose -Message 'Reboot required, setting DSCMachineStatus=1'
                    $global:DSCMachineStatus = 1
                }
                if ($null -ne (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue))
                {
                    Write-Verbose -Message 'PendingFileRenameOperations, setting DSCMachineStatus=1'
                    $global:DSCMachineStatus = 1
                }
            }

            # return true if the node is up-to-date
            TestScript = {
                $Path = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
                if ($null -eq (Get-ItemProperty -Path $Path -Name InstalledInstances -ErrorAction SilentlyContinue))
                {
                    Write-Verbose -Message 'Sql Server not installed.'
                    return $true
                }

                $Path = '{0}\{1}\MSSQLServer' -f $Path, $using:SqlInstanceData
                if (Test-Path -Path $Path -Verbose)
                {
                    # use BackupDirectory as it is the only registry key that contains the path we use.
                    Write-Verbose -Message 'SQL Server is installed, checking BackupDirectory path.'
                    if ($using:SqlBackupDir -eq (Get-ItemProperty -Path $Path -Name BackupDirectory).BackupDirectory)
                    {
                        Write-Verbose -Message 'Expected BackupDirectory path found.'
                        return $true
                    }
                    $BackupDirectory = (Get-ItemProperty -Path $Path -Name BackupDirectory).BackupDirectory
                    Write-Verbose -Message "BackupDirectory='$BackupDirectory'"
                }
                Write-Verbose -Message 'Uninstalling SQL Server.'
                return $false
            }
        }

        # create striped data disk
        Script SetupDataDisk
        {
            GetScript = {
                @{ Result = $true }
            }

            SetScript = {
                $PhysicalDisks = Get-StorageSubSystem -FriendlyName "Windows Storage*" | Get-PhysicalDisk -CanPool $True
                # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sql/virtual-machines-windows-sql-performance#disks-guidance
                $Partition = New-StoragePool -FriendlyName $using:SqlPoolName -StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks $PhysicalDisks |
                             New-VirtualDisk -FriendlyName $using:SqlDiskName -Interleave 64KB -NumberOfColumns 2 -ResiliencySettingName Simple -UseMaximumSize |
                             Initialize-Disk -PartitionStyle GPT -PassThru |
                             New-Partition -UseMaximumSize -DriveLetter $using:DataDiskDriveLetter[0] | 
                             Format-Volume -FileSystem NTFS -NewFileSystemLabel $using:SqlDiskName -AllocationUnitSize 64KB -Confirm:$false
            }

            # return true if the node is up-to-date
            TestScript = {
                $PhysicalDisks = Get-PhysicalDisk -CanPool $true -ErrorAction SilentlyContinue
                $StoragePool = Get-StoragePool -FriendlyName $using:SqlPoolName -ErrorAction SilentlyContinue
                if ($PhysicalDisks.Count -eq 2 -And $StoragePool -eq $null)
                {
                    return $false
                }
                return $true
            }
        }

        WaitForVolume WaitForDataDisk
        {
            DriveLetter = $DataDiskDriveLetter[0]
            DependsOn   = @('[Script]SetupDataDisk')
        }

        File CreateSqlBackupDirectory
        {
            Ensure             = 'Present'
            Type               = 'Directory'
            DestinationPath = $SqlBackupDir
            DependsOn       = @('[WaitForVolume]WaitForDataDisk')
        }

        cNtfsPermissionEntry SqlBackupDirPermissions
        {
            Ensure    = 'Present'
            Path      = $SqlBackupDir
            Principal = $SqlServiceAccount.UserName
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'FullControl'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = @('[xADUser]CreateSqlServerServiceAccount','[File]CreateSqlBackupDirectory')
        }

        File CreateSqlDataDirectory
        {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $SqlDataDir
            DependsOn       = @('[WaitForVolume]WaitForDataDisk')
        }

        cNtfsPermissionEntry SqlDataDirPermissions
        {
            Ensure    = 'Present'
            Path      = $SqlDataDir
            Principal = $SqlServiceAccount.UserName
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'FullControl'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = @('[xADUser]CreateSqlServerServiceAccount','[File]CreateSqlDataDirectory')
        }

        File CreateSqlLogDirectory
        {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $SqlLogDir
            DependsOn       = @('[WaitForVolume]WaitForDataDisk')
        }

        cNtfsPermissionEntry SqlLogDirPermissions
        {
            Ensure    = 'Present'
            Path      = $SqlLogDir
            Principal = $SqlServiceAccount.UserName
            AccessControlInformation = @(
                cNtfsAccessControlInformation
                {
                    AccessControlType = 'Allow'
                    FileSystemRights = 'FullControl'
                    Inheritance = 'ThisFolderSubfoldersAndFiles'
                    NoPropagateInherit = $false
                }
            )
            DependsOn = @('[xADUser]CreateSqlServerServiceAccount','[File]CreateSqlLogDirectory')
        }

        SqlSetup InstallSqlServer
        {
            InstanceName            = $SqlInstanceName
            Features                = 'SQLEngine,Replication,FullText,IS'
            SourcePath              = 'C:\SQLServerFull'
            ForceReboot             = $true
            InstallSharedDir        = 'C:\Program Files\Microsoft SQL Server'
            SQLBackupDir            = "$DataDiskDriveLetter\Backup"
            SQLTempDBDir            = "$DataDiskDriveLetter\Data"
            SQLTempDBLogDir         = "$DataDiskDriveLetter\Log"
            SQLUserDBDir            = "$DataDiskDriveLetter\Data"
            SQLUserDBLogDir         = "$DataDiskDriveLetter\Log"
            SecurityMode            = 'SQL'
            SAPwd                   = $SqlSa
            AgtSvcAccount           = $SqlServiceAccount
            SQLSvcAccount           = $SqlServiceAccount
            SQLSysAdminAccounts     = @($SqlServiceAccount.UserName,$DomainAdmin.UserName)
            PsDscRunAsCredential    = $DomainAdmin
            DependsOn               = @('[cNtfsPermissionEntry]SqlBackupDirPermissions','[cNtfsPermissionEntry]SqlDataDirPermissions','[cNtfsPermissionEntry]SqlLogDirPermissions','[UserRightsAssignment]AssignLogOnAsServiceRight')
        }

        SqlServerLogin AddClusterSvcAccountToSqlServer
        {
            Ensure               = 'Present'
            Name                 = $ClusterService
            LoginType            = 'WindowsUser'
            ServerName           = $env:COMPUTERNAME
            InstanceName         = $SqlInstanceName
            PsDscRunAsCredential = $DomainAdmin
            DependsOn            = @('[SqlSetup]InstallSqlServer')
        }

        SqlServerPermission AssignClusterSvcPermissions
        {
            Ensure               = 'Present'
            InstanceName         = $SqlInstanceName
            Principal            = $ClusterService
            Permission           = @('ConnectSql','AlterAnyAvailabilityGroup','ViewServerState')
            PsDscRunAsCredential = $DomainAdmin
            DependsOn            = @('[SqlServerLogin]AddClusterSvcAccountToSqlServer')
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
                    $params = @('-D', $spn, $using:ComputerName)
                    Write-Verbose ("setspn.exe {0}" -f ($params -join ' '))
                    $result = Start-Process -FilePath 'setspn.exe' -ArgumentList $params -NoNewWindow -PassThru -Wait
                    Write-Verbose "setspn.exe returned $($result.ExitCode)"

                    $params = @('-A', $spn, $using:ComputerName)
                    Write-Verbose ("setspn.exe {0}" -f ($params -join ' '))
                    $result = Start-Process -FilePath 'setspn.exe' -ArgumentList $params -NoNewWindow -PassThru -Wait
                    Write-Verbose "setspn.exe returned $($result.ExitCode)"
                }
            }

            TestScript = {
                $false
            }

            PsDscRunAsCredential = $DomainAdmin
            DependsOn            = @('[SqlSetup]InstallSqlServer')
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
                    $user = '{0}\{1}$' -f $using:DomainNetbiosName, $using:ClusterName
                    $PermsList = @('GR','CC;computer')
                    foreach ($permission in $PermsList)
                    {
                        $params = @($ou, '/I:T', '/G', '"{0}:{1}"' -f $user, $permission)
                        Write-Verbose ("dsacls.exe {0}" -f ($params -join ' '))
                        $result = Start-Process -FilePath 'dsacls.exe' -ArgumentList $params -NoNewWindow -PassThru -Wait
                        Write-Verbose "dsacls.exe returned $($result.ExitCode)"
                    }
                }

                TestScript = {
                    return $false
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

Function Get-DataDisk
{
    $Drives = Get-ChildItem -Path function:[f-z]: -n
    foreach ($Drive in $Drives)
    {
        if ((Test-Path "$Drive\Backup") -and (Test-Path "$Drive\Data") -and (Test-Path "$Drive\Log"))
        {
            return $Drive
        }
    }
    # use first available
    $Drives | Where{-Not(Test-Path $_)} | Select -First 1
}
