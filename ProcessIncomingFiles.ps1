#######################################################
###                                                 ###
###  Filename: ProcessIncomingFiles.ps1             ###
###  Author:   Craig Boroson                        ###
###  Version:  1.0                                  ###
###  Date:     March 26, 2017                       ###
###  Purpose:  Encrypt and transfer files from      ###
###            and External SFTP server to an       ###
###            internal NAS Share.                  ###
###                                                 ###
#######################################################

# Import the SSH/SFTP module to make the cmdlets available
import-module posh-ssh

# Import the function to write to log files
Import-Module C:\scripts\Function-Write-Log.psm1

# Import the function to validate the input file
Import-Module C:\scripts\validateinputs.psm1

# Load the list of vendors, paths and keynames
$vendors = Import-Csv -Path c:\scripts\vendors.csv


function setcredentials ( $vendor, $username, $password ) {

    $credpath = "c:\keys\$vendor-$username.xml"
    New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -AsPlainText -Force $password)) | Export-CliXml $credpath

}


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

# Decrypt a file
function decrypt ( $file, $target ) {
    try {
        Start-Process "C:\Program Files (x86)\GNU\GnuPG\pub\gpg.exe" -ArgumentList "--batch --yes --always-trust --passphrase $Passphrase --output $target --decrypt $file" -Wait -NoNewWindow
    }

    catch {
        Write-Log -Path $logfile -Level Error -Message = $_.Exception.Message
        $RunStatus = "Failure"
    }
}

function sendemail ($to, $attachment, $Status) {
        Send-MailMessage -Attachments $attachment `
                         -From "FileMover@jefferson.edu" `
                         -to $to `
                         -Subject "${Status}: Incoming sftp tranfer job" `
                         -Body "The job ended with the status of $Status.  The log file for the run is attached." `
                         -smtpserver smtp.jefferson.edu
}

function endscript {
# Close connections
    Get-SFTPSession | Remove-SFTPSession
    Stop-Transcript

    if ($RunStatus -ne "Success") {
        sendemail -to "linuxadmin@jefferson.edu" -attachment $sessionLogFile -Status $RunStatus
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
        write-output "Pull incoming scripts to third-party vendors.`r`n`r`nSyntax:`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) [vendor name]`r`n     Pull incoming files from specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) all-vendors`r`n     Pull incoming files from all known specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-vendors`r`n     Print list of known vendors`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-paths`r`n     Print list of source and target directories`r`n"

        Exit
        }

    list-vendors {
        write-output $vendors | Select-Object name,incomingenabled,outgoingenabled,EmailRecipients,AlwaysSendEmail | sort Name | Format-Table -Property * -AutoSize | Out-String -width 200
        Exit
        }

    list-paths {
        write-output $vendors | Select-Object name,IncomingNASDirectory,IncomingSFTPHost,IncomingSFTPDirectory,IncomingEncryption | sort Name | Format-Table -Property * -AutoSize | Out-String -width 200
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
        write-output "Pull incoming scripts to third-party vendors.`r`n`r`nSyntax:`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) [vendor name]`r`n     Pull incoming files from specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) all-vendors`r`n     Pull incoming files from all known specified vendor`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-vendors`r`n     Print list of known vendors`r`n"
        write-output "`r`n.\$($MyInvocation.MyCommand.Name) list-paths`r`n     Print list of source and target directories`r`n"

        Exit
        }
            
    }
}

# Begin logging
$sessionLogFile = "C:\logs\incoming\session\IncomingSessionLog_$(get-date -format MM-dd-yyyy).log"
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

# Get private key passphrase from encrypted file
$Passphrase = getcredentials -vendor "TJUH" -username "PrivateKeyPassphrase"

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

    # Set the alert flag at the start of the job
    $RunStatus = "Success"

    # Create log file with the name bassed on the date
    $logfile = "C:\logs\incoming\ProcessIncomingFiles_$($vendor.name)_$(get-date -format MM-dd-yyyy).log"

    # Set email recipients
    $EmailRecipients = $($vendor.EmailRecipients).split(";")

    Write-Log -Path $logfile -Level Info -Message "***************************************"
    Write-Log -Path $logfile -Level Info -Message "Beginning run to process incoming files"
    Write-Log -Path $logfile -Level Info -Message "***************************************"


    if ($vendor.IncomingEnabled -match "true") {

        Write-Log -Path $logfile -Level Info -Message "Processing vendor $($vendor.name)"
        Write-Log -Path $logfile -Level Info -Message "---------------------------------------"

        # Retrieve vendor password from encrypted file
        $password = getcredentials -vendor $vendor.name -username $vendor.IncomingUser

        if ($password -eq "Error") {
            Write-Log -Path $logfile -Level Error -Message "Failed to retrieve password from encrypted file for vendor $($vendor.name).  Skipping file transfer for this vendor."
            $RunStatus = "Failure"
            continue
        }

        if ($password -eq "Not Found"-and $Vendor.IncomingEncryption -eq "TRUE") {
            Write-Log -Path $logfile -Level Error -Message "Password file not found for vendor $($vendor.name).  Skipping file transfer for this vendor."
            $RunStatus = "Failure"
            continue
        }

        if ($password -eq "Not Found"-and $Vendor.IncomingEncryption -ne "TRUE") {
            Write-Log -Path $logfile -Level info -Message "Password file not found for vendor $($vendor.name), but encryption is not enabled.  Processing for this vendor will continue."
        }
            

        # Open session to target SFTP host
        $SessionID = OpenSFTPSession -username $vendor.IncomingUser -password $password -server $vendor.IncomingSFTPHost -port $Vendor.IncomingSFTPPort

        # Verify session opened properly
        if ($SessionID.GetType().Name -ne "Int32") {
            Write-Log -Path $logfile -Level Error -Message "Failed to open SFTP session to $($vendor.IncomingSFTPHost).  Skipping file transfer for this vendor."
            $RunStatus = "Failure"
            Continue
        }
        else {
            Write-Log -Path $logfile -Level Info -Message "Successfully opened SFTP session to $($vendor.IncomingSFTPHost)."
        }

        # Append trailing backslash to NAS directory if it doesn't exist
        if ($Vendor.IncomingNASDirectory.substring($Vendor.incomingNASDirectory.length-1) -ne "\") {
            $Vendor.IncomingNASDirectory += "\"
        }

        # Enumerate the files to be processed
        $FilesToProcess = ""
        $FilesToProcess = Get-SFTPChildItem -SessionId $SessionID -Path $Vendor.IncomingSFTPDirectory -Recursive | where {$_.isRegularFile -eq $true}

        if ($FilesToProcess -eq "") {
            Write-Log -Path $logfile -Level Info -Message "No incoming files found from $($vendor.name)."
        }

        Foreach ($File in $FilesToProcess) {
            Write-Log -Path $logfile -Level Info -Message "*** Processing file $($file.fullname)"

            # ***********************************
            # *** STEP 1: Download the file   ***
            # ***********************************

            $NASDirectory =$vendor.IncomingNASDirectory
            $TempFileName = $env:TEMP + "\" + $file.name

            # Copy the encrypted file from the external sftp server
            Get-SFTPFile -SessionId $SessionID -RemoteFile $File.FullName -LocalPath $env:TEMP -Overwrite

            # Verify the presence of the file on the local temp folder
            If (Test-Path $TempFileName) {
                Write-Log -Path $logfile -Level Info -Message "Step 1 - Retrieved successfully"
                $FileCopyStatus = "good"
            }
            else {
                Write-Log -Path $logfile -Level Error -Message "Step 1 - File $($File.fullname) could not be verified.  The transfer of this file did not succeed."
                $RunStatus = "Failure"
                $FileCopyStatus = "bad"
                continue
            }

            # **********************************
            # *** STEP 2: Decrypt the file   ***
            # **********************************

            # We have to assume that the customer will name encrypted files with a .gpg extension.
            # Also, there is no native way in Windows to detect if a file is encrypted.
            # Therefore, we are going to assume that all files are encrypted for those vendors who
            # are enabled for encryption.
            if ($TempFileName.Substring($TempFileName.Length-4,4) -eq ".gpg") {
                
                # Derrive the filename of the decrypted file by dropping the last four characters ".gpg"
                $CleartextFile = $TempFileName.Substring(0,$TempFileName.Length-4)  

                # Decrypt the file
                decrypt -file $TempFileName -target $CleartextFile

                # Verify the presence of the decrypted file on the source
                If (test-path $CleartextFile) {
                    Write-Log -Path $logfile -Level Info -Message "Step 2 - Decrypted successfully"

                    # Store filenames for later use
                    $CleartextFileShortName = $file.Name.Substring(0,$file.name.Length-4)
                    $NASFile = $Vendor.IncomingNASDirectory + $CleartextFileShortName


                    # ******************************************
                    # *** STEP 3: Delete encrypted file      ***
                    # ******************************************
                    # Delete the encrypted file if it was created
                    If (Test-Path $TempFileName) {Remove-Item $TempFileName}

                    # Verify that the encrypted file was deleted on the temp folder
                    If (test-path $TempFileName) {
                        Write-Log -Path $logfile -Level Warn -Message "Step 3 - File $TempFileName could not be deleted from the NAS Share.  This may create issues on future runs."
                        $RunStatus = "Failure"
                    }
                    else {
                        Write-Log -Path $logfile -Level Info -Message "Step 3 - Encrypted source file deleted successfully"
                    }

                }

                # File did not decrypt
                else {
                    Write-Log -Path $logfile -Level Error -Message "Step 2 - Decryption of file $($File.name) did not succeed."
                    $RunStatus = "Failure"
                    continue
                }

            }
            # File sent to us was not encypted
            else {
                Write-Log -Path $logfile -Level Info -Message "Step 2 - .gpg extension not detected.  Skipping file decryption and Step 3."
                $CleartextFile = $TempFileName
                $CleartextFileShortName = $File.Name
                $NASFile = $Vendor.IncomingNASDirectory + $CleartextFileShortName
            }

            # ******************************************
            # *** STEP 4: Create target directory    ***
            # ******************************************

            # Derive the full path for the target file
            # This command takes the full path on the NAS share and derrives the path and file names,
            # and replaces backslashes with forward slashes.
            
            $TargetFileFullName = $($file.FullName.Substring($vendor.IncomingSFTPDirectory.Length)).replace("/","\")
            $TargetPathOnly = $TargetFileFullName.Substring(0,$TargetFileFullName.IndexOf($ClearTextFileShortName)-1)
            $targetPath = $Vendor.IncomingNASDirectory + $targetpathonly
            $targetPathandfile = $TargetPath + "\" + $ClearTextFileShortName

            # Create target path if it doesn't exist
            if (!$(Test-Path $targetPath)) {
                Write-Log -Path $logfile -Level Info -Message "Step 4 - Creating directory on target for $targetpath."                
                New-Item -path $targetpath -type Directory
            }
            else {
                Write-Log -Path $logfile -Level Info -Message "Step 4 - Directory $targetpath already exists on target. Skipping directory creation."                
            }


            # ******************************************
            # *** STEP 5: Move the clear text file   ***
            # ******************************************

            # At this point, we have either a decrypted file or a file that came to us in clear text
            # The full path to that file is stored in the $CleartextFile variable
            # Move the cleartext file from the temp location to the NAS Share

            # Check for presence of existing file on NAS Share before downloading
            if (test-path $targetPathandfile) {
                $RenamedFile = $CleartextFileShortName + "_RENAMED_ON_" + $(get-date -Format MM-dd-yyyy)
                Rename-Item -Path $targetPathandfile -NewName $RenamedFile
                Write-Log -Path $logfile -Level Warn -Message "File $targetPathandfile already existed when the job ran.  The existing file was renamed to $RenamedFile ."
            }

            Move-Item -Path $CleartextFile -Destination $targetPath -Force

            # Verify the presence of the decrypted file on the NAS Share
            If (test-path $targetPathandfile) {Write-Log -Path $logfile -Level Info -Message "Step 5 - Moved to NAS Share successfully"}
            else {
                Write-Log -Path $logfile -Level Error -Message "Step 5 - File $targetPathandfile could not be verified.  Moving this file to the NAS share did not succeed."
                $RunStatus = "Failure"
            }


            # ****************************************
            # *** STEP 6: Delete the source file   ***
            # ****************************************

            # Delete the source file on the target if the file was retrieved properly
            if ($FileCopyStatus -eq "good") {
                Remove-SFTPItem -SessionId $SessionID -Path $file.FullName
            }
            
            # Verify the source file was deleted from the incoming folder
            If (Test-SFTPPath -sessionid $SessionID -path $file.FullName) {
                Write-Log -Path $logfile -Level Error -Message "Step 6 - File $($file.fullname) was still present on $($vendor.IncomingSFTPHost) after an attempt to delete it from the incoming folder on the source."
                $RunStatus = "Failure"
            }
            else {
                Write-Log -Path $logfile -Level Info -Message "Step 6 - Deleted from the source directory successfully"
            }

            
        } # end foreach file

    
    } # end if vendor.Incomingenabled
    
    # Vendor is disabled
    else {
        Write-Log -Path $logfile -Level Warn -Message "Skipping disabled vendor $($vendor.name)"
        Write-Log -Path $logfile -Level Info -Message "---------------------------------------"
        $RunStatus = "Warning"
    }

    # Close SFTP Session
    Remove-SFTPSession -SessionId $SessionID
    Write-Log -Path $logfile -Level Info -Message "Successfully closed SFTP session to $($vendor.IncomingSFTPHost)."

    if ($RunStatus -ne "Success" -or $vendor.AlwaysSendEmail -match "TRUE") {
        sendemail -to $vendor.EmailRecipients -attachment $logfile -Status $RunStatus
    }

} # end foreach vendor


endscript
