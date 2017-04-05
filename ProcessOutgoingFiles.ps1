#######################################################
###                                                 ###
###  Filename: ProcessOutgoingFiles.ps1             ###
###  Author:   Craig Boroson                        ###
###  Version:  1.0                                  ###
###  Date:     March 26, 2017                       ###
###  Purpose:  Encrypt and transfer files from      ###
###            and internal NAS share to an         ###
###            external SFTP server.                ###
###                                                 ###
#######################################################

# Import the SSH/SFTP module to make the cmdlets available
import-module posh-ssh

# Import the function to write to log files
Import-Module C:\scripts\Function-Write-Log.psm1

# Import the function to validate the input file
Import-Module C:\scripts\validateinputs.psm1

# Import the function to retrieve credentials
Import-Module C:\scripts\Function-Credentials.psm1

# Load the list of vendors, paths and keynames
$vendors = Import-Csv -Path c:\scripts\vendors.csv


# Open SFTP session with remote Linux host
function OpenSFTPsession ( $username, $password, $server, $port ) {

    if (!$port) {$port = 22}

    if ($password -eq "use key") {
        $keyfile = "c:\keys\$($vendor.name)-${username}.key"
        $pw = $password | convertto-securestring -AsPlainText -Force
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $pw

        $Session = New-SFTPSession -ComputerName $server -Credential $cred -Verbose -AcceptKey -port $port -KeyFile $keyfile
        
    }
    else {
        $pw = $password | convertto-securestring -AsPlainText -Force
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $pw

        $Session = New-SFTPSession -ComputerName $server -Credential $cred -Verbose -AcceptKey -port $port
    }

    Return $session.SessionID

}


# Encrypt a file
function encrypt ( $file, $recipient ) {
    try {
        Start-Process "C:\Program Files (x86)\GNU\GnuPG\pub\gpg.exe" -ArgumentList "--batch --yes --recipient $recipient --always-trust --output $($file + '.gpg') --encrypt $file" -Wait -NoNewWindow
    }

    catch {
        Write-Log -Path $logfile -Level Error -Message = $_.Exception.Message
        $RunStatus = "Failure"
    }
}

function sendemail ($to, $Status, $vendor, $log) {
        Send-MailMessage -From "FileMover@jefferson.edu" `
                         -to $to `
                         -Subject "${Status}: $vendor Incoming file tranfer job" `
                         -Body "The job ended with the status of $Status.`r`n`r`n$(get-content $log | out-string)" `
                         -smtpserver smtp.jefferson.edu
}

function endscript {
# Close connections
    Get-SFTPSession | Remove-SFTPSession
    Stop-Transcript

    if ($RunStatus -ne "Success") {
        sendemail -to "linuxadmin@jefferson.edu" -log $sessionLogFile -Status $RunStatus -vendor ""
    }

    Exit
}


#####################
### End Functions ###
#####################




#########################
### Process Arguments ###
#########################

$argument = $args[0]
# Display help information if no script argument was provided
switch ($argument) {

     help {
        write-output "Push outgoing scripts to third-party vendors.`r`n`r`nSyntax:`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) [vendor name]`r`n     Send outgoing files to specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) all-vendors`r`n     Send outgoing files to all known specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-vendors`r`n     Print list of known vendors`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-paths`r`n     Print list of source and target directories`r`n"

        Exit
        }

    list-vendors {
        write-output $vendors | Select-Object name,incomingenabled,outgoingenabled,EmailRecipients,AlwaysSendEmail | sort Name | Format-Table -Property * -AutoSize | Out-String -width 200
        Exit
        }

    list-paths {
        write-output $vendors | Select-Object name,OutgoingNASDirectory,OutgoingSFTPHost,OutgoingSFTPDirectory,OutgoingEncryption | sort Name | Format-Table -Property * -AutoSize | Out-String -width 200
        Exit
        }

    all-vendors {
        write-output "All vendors will be processed in this run"
        }

    default {
        If ($vendors.name -contains $argument) {
            write-output "Only vendor $argument will be processed in this run"
            $vendors = $vendors | where {$_.name -eq $argument}
        }
        elseif ($args[0] -ne $null) {
            write-output "Vendor $argument was not found in the configuration.`r`nUse the 'list-vendors' argument to show the available vendors, or configure the input file appropriately."
            Exit
        }
        else {
        write-output "Push outgoing scripts to third-party vendors.`r`n`r`nSyntax:`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) [vendor name]`r`n     Send outgoing files to specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) all-vendors`r`n     Send outgoing files to all known specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-vendors`r`n     Print list of known vendors`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-paths`r`n     Print list of source and target directories`r`n"

        Exit
        }
            
    }
}

# Begin logging
$sessionLogFile = "C:\logs\outgoing\session\OutgoingSessionLog_$(get-date -format MM-dd-yyyy).log"
Start-Transcript -Path $sessionLogFile -Append


# Validate the contents input file
# Note:  This can only catch data entry mistakes that invalidate certain rules.
#        It will check that the data is in the correct format. However, it
#        cannot check to make sure the correct source and target paths have been
#        entered, or that the vendor name is correct since it is the function of
#        the input file to tell the script to provide that information.
$result = validateinputs $vendors
if ($result -contains "fail") {
    $RunStatus = "Configuration file failed validation"

    endscript
}



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


# Process Outgoing Files
foreach ($vendor in $vendors) {

    # Set the alert flag at the start of the job
    $RunStatus = "Success"

    # Create log file with the name bassed on the date
    $logfile = "C:\logs\outgoing\ProcessOutgoingFiles_$($vendor.name)_$(get-date -format MM-dd-yyyy).log"

    # Set email recipients
    $EmailRecipients = $($vendor.EmailRecipients).split(";")

    Write-Log -Path $logfile -Level Info -Message "***************************************"
    Write-Log -Path $logfile -Level Info -Message "Beginning run to process outgoing files"
    Write-Log -Path $logfile -Level Info -Message "***************************************"


    if ($vendor.Outgoingenabled -match "true") {

        Write-Log -Path $logfile -Level Info -Message "Processing vendor $($vendor.name)"
        Write-Log -Path $logfile -Level Info -Message "---------------------------------------"

        # Retrieve vendor password from encrypted file
        $password = getcredentials -vendor $vendor.name -username $vendor.OutgoingUser

        if ($password -eq "Error") {
            Write-Log -Path $logfile -Level Error -Message "Failed to retrieve password from encrypted file for vendor $($vendor.name).  Skipping file transfer for this vendor."
            $RunStatus = "Failure"
            continue
        }

        if ($password -eq "Not Found"-and $Vendor.OutgoingEncryption -eq "TRUE") {
            Write-Log -Path $logfile -Level Error -Message "Password file not found for vendor $($vendor.name).  Skipping file transfer for this vendor."
            $RunStatus = "Failure"
            continue
        }

        if ($password -eq "Not Found"-and $vendor.OutgoingEncryption -ne "TRUE") {
            Write-Log -Path $logfile -Level info -Message "Password file not found for vendor $($vendor.name), but encryption is not enabled.  Processing for this vendor will continue."
        }
            

        # Open session to target SFTP host
        $SessionID = OpenSFTPSession -username $vendor.OutgoingUser -password $password -server $vendor.OutgoingSFTPHost -port $Vendor.OutgoingSFTPPort

        # Verify session opened properly
        if ($SessionID.GetType().Name -ne "Int32") {
            Write-Log -Path $logfile -Level Error -Message "Failed to open SFTP session to $($vendor.OutgoingSFTPHost).  Skipping file transfer for this vendor."
            $RunStatus = "Failure"
            Continue
        }
        else {
            Write-Log -Path $logfile -Level Info -Message "Successfully opened SFTP session to $($vendor.OutgoingSFTPHost)."
        }


        # Look for files with spaces in the name and replace them with underscores
        get-childitem $vendor.OutgoingNASDirectory -Exclude "*.gpg" -File -Recurse | where {$_.DirectoryName -notmatch "archive" -AND $_.name -match " "} | foreach {
            $New=$_.name.Replace(" ","_")
            Rename-Item -path $_.Fullname -newname $New -passthru
            Write-Log -Path $logfile -Level Info -Message "Renamed file $($_.fullname) with space to $new"       
        }


        # Enumerate the files to be processed
        $FilesToProcess = get-childitem $vendor.OutgoingNASDirectory -File -Recurse | where {$_.DirectoryName -notmatch "archive"}

        if ($FilesToProcess -eq $null -and $vendor.NoFilesIsError -eq "TRUE") {
            Write-Log -Path $logfile -Level Warn -Message "No outgoing files found for $($vendor.name)."
            $RunStatus = "No files found"
        }

        if ($FilesToProcess -eq $null -and $vendor.NoFilesIsError -eq "FALSE") {
            Write-Log -Path $logfile -Level Info -Message "No outgoing files found for $($vendor.name)."
        }

        Foreach ($File in $FilesToProcess) {
            Write-Log -Path $logfile -Level Info -Message "*** Processing file $($file.fullname)"


            If ($vendor.OutgoingEncryption -match "true" -and $file.Extension -ne ".gpg") {
                # **********************************
                # *** STEP 1: Encrypt the file   ***
                # **********************************

                # Test for presense of an encrypted file with the same name that doesn't belong
                $NewFullName = $file.fullname + '.gpg'
                $NewShortName = $file.name + '.gpg'
                if (test-path $NewFullName) {
                    $RenamedFile = $NewShortName + "_RENAMED_ON_" + $(get-date -Format MM-dd-yyyy) + ".gpg"
                    Rename-Item -Path $NewFullName -NewName $RenamedFile
                    Write-Log -Path $logfile -Level Warn -Message "File $NewFullName already existed when the job ran.  The existing file was renamed to $RenamedFile ."
                }


                # Note: the GPG command line can't process backslashes on network shares.
                #       Therefore, they are converted to forward slashes below.
                encrypt -file $($file.fullname -replace "\\","/") -recipient $Vendor.keyname


                # Verify the presence of the encrypted file on the source
                If (test-path $NewFullName) {
                    Write-Log -Path $logfile -Level Info -Message "Step 1 - Encrypted successfully"
                    $Extension = ".gpg"
                }
                else {
                    Write-Log -Path $logfile -Level Error -Message "Step 1 - File $NewFullName could not be verified.  The encryption of this file did not succeed."
                    $RunStatus = "Failure"
                    Continue
                }
            }
            else {
                Write-Log -Path $logfile -Level Info -Message "Step 1 - Bypassing encryption for file $($file.name) because the vendor is not enabled for encryption or the filename ends with .gpg"
                $NewFullName = $file.fullname
                $NewShortName = $file.name
                $extension = ""
            }

            # **********************************
            # *** STEP 2: Copy the file      ***
            # **********************************

            # Derive the full path for the target file
            # This command takes the full path on the NAS share and identifies where the word "outgoing" is.
            # It then takes the content to the right of the word "outgoing" and replaces backslashes with
            # forward slashes.
            $TargetFileFullName = $($file.fullname.substring($file.fullname.indexof("\outgoing\")+9)).replace("\","/") + $Extension
            $TargetPathOnly = $TargetFileFullName.Substring(0,$TargetFileFullName.IndexOf($NewShortName)-1)
            $targetPath = $Vendor.OutgoingSFTPDirectory + $targetpathonly
            $targetPathandfile = $TargetPath + "/" + $NewShortName

            # Create target path if it doesn't exist
            if (!$(Test-SFTPPath -SessionId $SessionID -path $targetPath)) {
                Write-Log -Path $logfile -Level Info -Message "Step 2a - Creating directory on target for $targetpath."                
                New-SFTPItem -ItemType Directory -SessionId $SessionID -Path $targetpath -Recurse -Verbose
            }
            else {
                Write-Log -Path $logfile -Level Info -Message "Step 2a - Directory $targetpath already exists on target."                
            }

            # Check if file already exists in the target

            if (Test-SFTPPath -sessionId $sessionID -Path $targetpathandfile) {
                # Append the date to the target file name to make it unique
                $renamedfile = $($newshortname + "_RENAMED_ON_" + $(get-date -format MM-dd-yyyy_HH-mm-ss))

                # Rename the target file
                Rename-SFTPFile -SessionId $SessionID -Path $targetpathandfile -NewName $renamedfile

                # Verify file was renamed
                If (Test-SFTPPath -SessionId $SessionID -Path $($targetpath + "/" + $RenamedFile)) {
                    Write-Log -Path $logfile -Level Warn -Message "A file by the name $($file.name) already existed in target folder.  Renamed file to $renamedfile"
                    $RunStatus = "Warning"
                }
                # Attempt to rename file failed
                else {
                    Write-Log -Path $logfile -Level Warn -Message "A file by the name $($file.name) already existed in target folder.  An attempt to rename the file to $renamedfile failed."
                    $RunStatus = "Warning"
                }                    
            }
                

            # Copy the encrypted file to the external sftp server
            Set-SFTPFile -SessionId $SessionID -LocalFile $NewFullName -RemotePath $targetPath -Overwrite

  
            # Verify the presence of the encrypted file on the target
            # NOTE: SOME VENDORS (e.g. nthrive) INGEST AND DELETE FILES FASTER THAN WE CAN VERIFY THEM

            if (Test-SFTPPath -SessionId $SessionID -Path $targetPathandFile) {
                Write-Log -Path $logfile -Level Info -Message "Step 2b - Sent successfully"
                $FileCopyStatus = "good"
            }
            else {
                Write-Log -Path $logfile -Level Warn -Message "Step 2b - File $targetfileFullName could not be verified.  Either the transfer of this file did not succeed or the vendor ingested and deleted the file before we could verify its presence on the target."
                $FileCopyStatus = "good" # this should be "bad" but can't be due to the vendor point stated above
            }

            # ******************************************
            # *** STEP 3: Delete encrypted file      ***
            # ******************************************
            
            # Delete the encrypted file if it was created
            if ($vendor.OutgoingEncryption -match "TRUE") {

                If (Test-Path $NewFullName) {Remove-Item $NewFullName}

                # Verify that the encrypted file was deleted on the source
                If (test-path $NewFullName) {
                    Write-Log -Path $logfile -Level Error -Message "Step 3 - File $NewFullName could not be deleted from the source.  This may create issues on future runs."
                    $RunStatus = "Failure"
                }
                else {
                    Write-Log -Path $logfile -Level Info -Message "Step 3 - Encrypted source file deleted successfully"
                }
            }

            # ************************************************
            # *** STEP 4: Archive the clear text file      ***
            # ************************************************

            # Move the cleartext file to the archive subfolder if it was successfully sent to the sftp server
            if ($FileCopyStatus -eq "good") {

                # Check if file already exists in the archive folder
                $targetfile = $($vendor.OutgoingNASDirectory + "\archive\" + $file.name)
                if (Test-Path $targetfile) {
                    # Append the date to the target file name to make it unique
                    $targetfile = $($targetfile + "_RENAMED_ON_" + $(get-date -format MM-dd-yyyy_HH-mm-ss))
                    Write-Log -Path $logfile -Level Warn -Message "Cleartext source file already existed in archive.  Renamed file to $targetfile"
                }
                
                # Archive the cleartext file  
                move-item $file.FullName $targetfile -force

                # Verify that the cleartext file was moved to the source archive
                $FileShouldExist = test-path $targetfile
                $FileShouldNotExist = test-path $file.fullName

                If ($FileShouldExist -eq $true -and $FileShouldNotExist -eq $false) {
                    Write-Log -Path $logfile -Level Info -Message "Step 4 - Cleartext source file archived successfully"
                }
                else {
                    Write-Log -Path $logfile -Level Error -Message "Step 4 - File $($File.FullName) could not be moved to the archive folder.  This may create issues on future runs."
                    $RunStatus = "Failure"
                }
            } # end move file

        } # end foreach vendor

        # Close SFTP Session
        Remove-SFTPSession -SessionId $SessionID
        Write-Log -Path $logfile -Level Info -Message "Successfully closed SFTP session to $($vendor.OutgoingSFTPHost)."

    } # end if statement for vendor.outgoingenabled
    else {
        Write-Log -Path $logfile -Level Warn -Message "Skipping disabled vendor $($vendor.name)"
        Write-Log -Path $logfile -Level Info -Message "---------------------------------------"
        $RunStatus = "Warning"
    }

    if ($RunStatus -ne "Success" -or $vendor.AlwaysSendEmail -match "TRUE") {
        sendemail -to $EmailRecipients -Status $RunStatus -vendor $vendor.name -log $logfile
    }

} # end foreach vendor

endscript
