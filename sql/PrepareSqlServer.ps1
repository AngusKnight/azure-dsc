Configuration PrepareSqlServer
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
        [System.Management.Automation.PSCredential]$SqlSa
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration,NetworkingDsc,SecurityPolicyDsc,SqlServer,SqlServerDsc,StorageDsc,xActiveDirectory
    
    $DomainNetbiosName=(Get-NetBiosName -DomainName $DomainName)
    $DomainAdmin = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($DomainAdmin.UserName)", $DomainAdmin.Password)
	$SqlServiceAccount = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SqlServiceAccount.UserName)", $SqlServiceAccount.Password)

	# find next available disk letter for Add disk
    $DataDiskDriveLetter = ls function:[f-z]: -n | ?{ !(test-path $_) } | select -First 1
    
    $SqlDiskName = 'SqlDisk01'
    $SqlInstanceName = 'MSSQLSERVER'
    $SqlInstanceData = 'MSSQL13.MSSQLSERVER'
	$SqlPath = Join-Path -Path $DataDiskDriveLetter -ChildPath SqlInstanceData
    $SqlPoolName = 'SqlPool01'
    
    Node localhost
    {
        LocalConfigurationManager 
        {
            RebootNodeIfNeeded = $true
        }

        Firewall DatabaseEngineFirewallRule
        {
            Ensure = 'Present'
			Action = 'Allow'
            Direction = 'Inbound'
            Name = 'SQL-Server-Database-Engine-TCP-In'
            DisplayName = 'SQL Server Database Engine (TCP-In)'
            Description = 'Inbound rule for SQL Server to allow TCP traffic for the Database Engine.'
            Group = 'SQL Server'
            Enabled = 'True'
            Protocol = 'TCP'
            LocalPort = '1433'
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
                    $BackupDirectory = '{0}\{1}\MSSQL\Backup' -f $using:DataDiskDriveLetter, $using:SqlInstanceData
                    if ($BackupDirectory -eq (Get-ItemProperty -Path $Path -Name BackupDirectory).BackupDirectory)
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
                             New-Partition -UseMaximumSize
                $Partition | Add-PartitionAccessPath -AccessPath $using:DataDiskDriveLetter
                $Partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel $using:SqlDiskName -AllocationUnitSize 64KB -Confirm:$false
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
			
			DependsOn = @('[Script]UninstallDefaultInstance')
        }

        xADUser CreateSqlServerServiceAccount
        {
            Ensure = 'Present'
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $SqlServiceAccount.UserName
            Password = $SqlServiceAccount
        }

        UserRightsAssignment AssignLogOnAsServiceRight
        {
            Policy    = 'Log_on_as_a_service'
            Identity  = $SqlServiceAccount.UserName
			DependsOn = @('[xADUser]CreateSqlServerServiceAccount')
        }

		File CreateSqlDirectory
		{
			Ensure 			= 'Present'
			Type   			= 'Directory'
			DestinationPath = $SqlPath
		}

        Script SqlDirectoryPermissions
        {
            # does nothing
            GetScript = {
                @{ Result = $true }
            }
            
            SetScript = {
                $ar = New-Object System.Security.AccessControl.FileSystemAccessRule($using:SqlServiceAccount.UserName, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
                $acl = Get-Acl -Path $using:SqlPath
                $acl.AddAccessRule($ar)
                Set-Acl -Path $using:SqlPath -AclObject $acl
            }
            
            # return true if the node is up-to-date
            TestScript = {
                $acl = Get-Acl -Path $using:SqlPath
                if ($acl.Access | Where-Object IdentityReference -eq $using:SqlServiceAccount.UserName)
                {
                    return $true
                }
                return $false
            }
            DependsOn = @('[File]CreateSqlDirectory')
        }

        SqlSetup InstallSqlServer
        {
            InstanceName            = $SqlInstanceName
            Features                = 'SQLEngine,Replication,FullText,IS'
            SourcePath              = 'C:\SQLServerFull'
            ForceReboot             = $true
            InstallSharedDir        = 'C:\Program Files\Microsoft SQL Server'
            InstallSQLDataDir       = $DataDiskDriveLetter
            SecurityMode            = 'SQL'
            SAPwd                   = $SqlSa
			AgtSvcAccount			= $SqlServiceAccount
			SQLSvcAccount			= $SqlServiceAccount
			SQLSysAdminAccounts		= @($SqlSa.UserName,$SqlServiceAccount.UserName,$DomainAdmin.UserName)
            PsDscRunAsCredential    = $DomainAdmin
            DependsOn               = @('[Script]SetupDataDisk','[UserRightsAssignment]AssignLogOnAsServiceRight','[Script]SqlDirectoryPermissions')
        }
    }
}

Function Get-NetBiosName
{ 
    param
    (
        [string]$DomainName
    )

    if ($DomainName.Contains('.'))
    {
        $length = $DomainName.IndexOf('.')
        if ( $length -ge 16)
		{
            $length = 15
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