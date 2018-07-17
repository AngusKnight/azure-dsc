Configuration PrepareSqlStorage
{
    param
    (
        [Parameter(Mandatory)]
        [string]$DataAccessPath,
        
        [Parameter(Mandatory)]
        [string]$DataDiskName,
        
        [Parameter(Mandatory)]
        [int]$DataDiskSizeGb,

        [Parameter(Mandatory)]
        [string]$LogsAccessPath,
        
        [Parameter(Mandatory)]
        [string]$LogsDiskName,
        
        [Parameter(Mandatory)]
        [int]$LogsDiskSizeGb,
        
        [Parameter(Mandatory)]
        [ValidateSet(64, 256)]
        [int]$Interleave = 64   
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration,StorageDsc
    
    Node localhost
    {
        WaitForDisk WaitForDisk2
        {
            DiskId = 2
        }
        
        WaitForDisk WaitForDisk3
        {
            DiskId = 3
        }
        
        WaitForDisk WaitForDisk4
        {
            DiskId = 4
        }
        
        WaitForDisk WaitForDisk5
        {
            DiskId = 5
        }
        
        # create striped data disk
        File SqlDataAccessPath
        {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $DataAccessPath
        }
        
        Script SetupDataStorage
        {
            GetScript = {
                @{ Result = $true }
            }
            
            SetScript = {
                $FriendlyName = $using:DataDiskName
                $PhysicalDisks = Get-PhysicalDisk -CanPool $True | Where Size -eq ($using:DataDiskSizeGb * 1GB)
                # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sql/virtual-machines-windows-sql-performance#disks-guidance
                $Partition = New-StoragePool -FriendlyName $FriendlyName -StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks $PhysicalDisks |
                             New-VirtualDisk -FriendlyName $FriendlyName -New-VirtualDisk ($using:Interleave * 1KB) -NumberOfColumns 2 -ResiliencySettingName Simple -UseMaximumSize |
                             Initialize-Disk -PartitionStyle GPT -PassThru |
                             New-Partition -UseMaximumSize
                $Partition | Add-PartitionAccessPath -AccessPath $using:DataAccessPath -PassThru | Set-Partition -NoDefaultDriveLetter $True
                $Partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel $FriendlyName -AllocationUnitSize 64KB -Confirm:$false
            }
            
            # return true if the node is up-to-date
            TestScript = {
                $FriendlyName = $using:DataDiskName
                $PhysicalDisks = Get-PhysicalDisk -CanPool $True -ErrorAction SilentlyContinue | Where Size -eq ($using:DataDiskSizeGb * 1GB)
                $StoragePool = Get-StoragePool -FriendlyName $FriendlyName -ErrorAction SilentlyContinue
                if ($PhysicalDisks.Count -eq 2 -And $StoragePool -eq $null)
                {
                    return $false
                }
                return $true
            }
            DependsOn = @('[File]SqlDataAccessPath','[WaitForDisk]WaitForDisk2','[WaitForDisk]WaitForDisk3','[WaitForDisk]WaitForDisk4','[WaitForDisk]WaitForDisk5')
        }
        
        # create striped logs disk
        File SqlLogsAccessPath
        {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $LogsAccessPath
        }
        
        Script SetupLogsStorage
        {
            GetScript = {
                @{ Result = $true }
            }
            
            SetScript = {
                $FriendlyName = $using:LogsDiskName
                $PhysicalDisks = Get-PhysicalDisk -CanPool $True | Where Size -eq ($using:LogsDiskSizeGb * 1GB)
                # https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sql/virtual-machines-windows-sql-performance#disks-guidance
                $Partition = New-StoragePool -FriendlyName $FriendlyName -StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks $PhysicalDisks |
                             New-VirtualDisk -FriendlyName $FriendlyName -Interleave ($using:Interleave * 1KB) -NumberOfColumns 2 -ResiliencySettingName Simple -UseMaximumSize |
                             Initialize-Disk -PartitionStyle GPT -PassThru |
                             New-Partition -UseMaximumSize
                $Partition | Add-PartitionAccessPath -AccessPath $using:LogsAccessPath -PassThru | Set-Partition -NoDefaultDriveLetter $True
                $Partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel $FriendlyName -AllocationUnitSize 64KB -Confirm:$false
            }
            
            # return true if the node is up-to-date
            TestScript = {
                $FriendlyName = $using:LogsDiskName
                $PhysicalDisks = Get-PhysicalDisk -CanPool $True -ErrorAction SilentlyContinue | Where Size -eq ($using:LogsDiskSizeGb * 1GB)
                $StoragePool = Get-StoragePool -FriendlyName $FriendlyName -ErrorAction SilentlyContinue
                if ($PhysicalDisks.Count -eq 2 -And $StoragePool -eq $null)
                {
                    return $false
                }
                return $true
            }
            DependsOn = @('[File]SqlLogsAccessPath','[WaitForDisk]WaitForDisk2','[WaitForDisk]WaitForDisk3','[WaitForDisk]WaitForDisk4','[WaitForDisk]WaitForDisk5')
        }
    }
}