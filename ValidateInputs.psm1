#######################################################
###                                                 ###
###  Filename: ValidateInputs.ps1                   ###
###  Author:   Craig Boroson                        ###
###  Version:  1.0                                  ###
###  Date:     March 27, 2017                       ###
###  Purpose:  Validate that the data pulled in     ###
###            from the spreadsheet meets certain   ###
###            acceptable criteria                  ###
###                                                 ###
#######################################################


function validateinputs ($vendors) {
    # Validate inputs to avoid Little Bobby Tables
    # https://xkcd.com/327/
    
    $response = ""
    $validatestatus = "pass"

        # Validate headers are correct
    If ($vendors[0].PSobject.Properties.Name -notcontains "Name" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingSFTPHost" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingSFTPPort" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingEnabled" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingNASDirectory" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingSFTPDirectory" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingEncryption" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingUser" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "IncomingPassword" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingSFTPHost" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingSFTPPort" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingEnabled" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingNASDirectory" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingSFTPDirectory" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingEncryption" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingUser" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "OutgoingPassword" `
        -or $vendors[0].PSobject.Properties.Name -notcontains "Keyname" ) {
        $response += "Validation of the headers in the spreadsheet failed.  Please ensure that the following headers are included:  Name,IncomingSFTPHost,IncomingSFTPPort,IncomingEnabled,IncomingNASDirectory,IncomingSFTPDirectory,IncomingEncryption,IncomingUser,IncomingPassword,OutgoingSFTPHost,OutgoingSFTPPort,OutgoingEnabled,OutgoingNASDirectory,OutgoingSFTPDirectory,OutgoingEncryption,OutgoingUser,OutgoingPassword,Keyname`r`n"
        $ValidateStatus = "fail"
    }

#    # Validate SFTPDirectories
#    $BadItems = ""
#    $BadItems = $vendors | where {$_.IncomingSFTPDirectory.substring(0,10) -notcontains "/home/ftp/"}
#    if ($BadItems) {
#        $response += "Validation of the SFTP directories in the spreadsheet failed.  The following entries failed validation: `r`n Name: $($BadItems.name) Directory: $($BadItems.SFTPDirectory)`r`n"
#        $ValidateStatus = "fail"
#    }

#    # Validate IncomingNASDirectories    
#    $BadItems = ""
#    $BadItems = $vendors | where {$_.IncomingNASDirectory.substring(0,3) -notcontains "z:\" -or $_.IncomingNASDirectory.substring($_.NASDirectory.Length-1) -ne "\"}
#    if ($BadItems) {
#        $response += "Validation of the NAS directories in the spreadsheet failed.  The following entries failed validation: `r`n Name: $($BadItems.name) Directory: $($BadItems.NASDirectory)`r`n"
#        $ValidateStatus = "fail"
#    }

    # Validate OutgoingEnabled    
    $BadItems = ""
    $BadItems = $vendors | where {$_.OutgoingEnabled -notmatch "TRUE|FALSE"}
    if ($BadItems) {
        $response += "Validation of the OutgoingEnabled column in the spreadsheet failed.  The following entries failed validation: `r`n Name: $($BadItems.name) Directory: $($BadItems.Enabled)`r`n"
        $ValidateStatus = "fail"
    }

    # Validate IncomingEnabled    
    $BadItems = ""
    $BadItems = $vendors | where {$_.IncomingEnabled -notmatch "TRUE|FALSE"}
    if ($BadItems) {
        $response += "Validation of the IncomingEnabled column in the spreadsheet failed.  The following entries failed validation: `r`n Name: $($BadItems.name) Directory: $($BadItems.Enabled)`r`n"
        $ValidateStatus = "fail"
    }

    # Validate OutgoingEncryption    
    $BadItems = ""
    $BadItems = $vendors | where {$_.OutgoingEncryption -notmatch "TRUE|FALSE"}
    if ($BadItems) {
        $response += "Validation of the OutgoingEncryption column in the spreadsheet failed.  The following entries failed validation: `r`n Name: $($BadItems.name) Directory: $($BadItems.EnableEncryption)`r`n"
        $ValidateStatus = "fail"
    }

    # Validate IncomingEncryption    
    $BadItems = ""
    $BadItems = $vendors | where {$_.IncomingEncryption -notmatch "TRUE|FALSE"}
    if ($BadItems) {
        $response += "Validation of the IncomingEncryption column in the spreadsheet failed.  The following entries failed validation: `r`n Name: $($BadItems.name) Directory: $($BadItems.EnableEncryption)`r`n"
        $ValidateStatus = "fail"
    }

    # Validate Keyname    
    $BadItems = ""
    $BadItems = $vendors | where {$_.keyname -notmatch "^[A-Z0-9]{8}$"}
    if ($BadItems) {
        $response += "Validation of the keyname column in the spreadsheet failed.  The following entries failed validation: `r`n Name: $($BadItems.name) Directory: $($BadItems.Keyname)`r`n"
        $ValidateStatus = "fail"
    }


    return $response, $validatestatus
}