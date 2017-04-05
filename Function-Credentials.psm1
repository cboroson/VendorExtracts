#######################################################
###                                                 ###
###  Filename: Function-Credentials.psm1            ###
###  Author:   Craig Boroson                        ###
###  Version:  1.0                                  ###
###  Date:     April 4, 2017                        ###
###  Purpose:  Save encrypted credentials to files  ###
###            Retrieve encrypted credentials       ###
###            from files.                          ###
###                                                 ###
#######################################################


function setcredentials ( $vendor, $username, $password ) {

    $credpath = "c:\keys\$vendor-$username.xml"
    New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -AsPlainText -Force $password)) | Export-CliXml $credpath

    Return "Password saved for $vendor-$username"

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