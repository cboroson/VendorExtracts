#######################################################
###                                                 ###
###  Filename: ArchiveCleanup.ps1                   ###
###  Author:   Craig Boroson                        ###
###  Version:  1.0                                  ###
###  Date:     March 27, 2017                       ###
###  Purpose:  Delete archived files and folders    ###
###            older than a set number of days.     ###
###                                                 ###
#######################################################

# Import the function to write to log files
Import-Module C:\scripts\Function-Write-Log.psm1

# Create log file with the name bassed on the date
$logfile = "C:\logs\cleanup\ArchiveCleanup_$(get-date -format MM-dd-yyyy).log"

# The following people will be sent the job log at the completion of the script
$EmailRecipients = "cboroson@hainc.com"
$AlwaysSendEmail = $false # Set to $false to only be notified on warnings or failures

# Set the alert flag at the start of the job
$RunStatus = "Success"

# Delete files older than X days
$Days = 90
$limit = (Get-Date).AddDays(-$Days)

# Load the list of vendors, paths and keynames
$vendors = Import-Csv -Path c:\scripts\vendors.csv


function getcredentials ( $vendor, $username ) {

    $credpath = "c:\keys\$vendor-$username.xml"
    if (Test-Path $credpath) {
        try {
            $ErrorActionPreference = "SilentlyContinue"
            $cred = import-clixml -path $credpath -ErrorAction SilentlyContinue
            $password = $cred.GetNetworkCredential().password
        }
        catch { 
            $ErrorActionPreference = "Stop"
            $password = "Error"
        }
    }    
    else {
        $password = "Not Found"
    }

    Return $password
}


#####################
### End Functions ###
#####################

# Begin logging
Start-Transcript -Path $LogFile -Append

write-output "************************************************************"
write-output "Beginning run to delete archive files older than $days days."
write-output "************************************************************"

# Disconnect existing network sessions to NAS Share
$Mappings = Get-SmbMapping
if ($mappings.RemotePath -eq "\\tjh.tju.edu\epic") {Remove-SmbMapping -remotePath \\tjh.tju.edu\epic -Force}
if ($mappings.RemotePath -eq "\\tjh.tju.edu\epic\prod-shares") {Remove-SmbMapping -remotePath \\tjh.tju.edu\epic\prod-shares -Force}

if ($mappings.RemotePath -ne "\\tjh.tju.edu\epic\prod-shares\external") {
    $username = "`$SA_EPEXTERNALXFER"
    $password = getcredentials -vendor TJUH -username `$SA_EPEXTERNALXFER

    # Map External NAS share
    new-SmbMapping -remotePath \\tjh.tju.edu\epic\prod-shares\external -UserName $username -Password $password
}

if ($mappings.RemotePath -ne "\\tjh.tju.edu\epic\prod-shares\internal") {
    $username = "`$SA_EPEXTERNALXFER"
    $password = getcredentials -vendor TJUH -username `$SA_EPEXTERNALXFER

    # Map internal NAS share
    new-SmbMapping -remotePath \\tjh.tju.edu\epic\prod-shares\internal -UserName $username -Password $password
}


# Process Incoming Files
foreach ($vendor in $vendors) {
    
    write-output "Processing vendor $($vendor.name)"
    write-output "---------------------------------------"

    $ArchiveFolder = $Vendor.NASDirectory 

    # Delete files older than the $limit.
    $FilesToDelete = Get-ChildItem -Path $ArchiveFolder -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt $limit -and $_.Directory.Name -eq "archive"}
    if ($FilesToDelete) {
        foreach ($file in $FilesToDelete) {
            # Delete file
            Remove-Item $file.FullName -Force 

            # Verify that file was deleted
            if (test-path $file.FullName) {
                write-output "ERROR: Deletion attempt failed for $($file.fullname)"
                $RunStatus = "Error"
            }
            else {
                write-output "Deleted $($file.fullname)"
            }
        }
    }
    else {
        write-output "No files found older than $days days."
    }

}

# Send logfile if Job encountered errors
if ($RunStatus -ne "Success" -or $AlwaysSendEmail -eq $true) {
    Send-MailMessage -Attachments $logfile `
                     -From "ArchiveCleanup@pgpencrypt01pa.tjh.tju.edu" `
                     -to $EmailRecipients `
                     -Subject "${RunStatus}: Archive Cleanup job" `
                     -Body "The job ended with the status of ${RunStatus}.  The log file for the full day is attached." `
                     -smtpserver smtp.jefferson.edu
    }

