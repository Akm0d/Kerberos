# Creator: Tyler Johnson
# Date: 6/28/2016
# Name: Kerberize.ps1
# Description: Creates a kerberos service principal in AD and saves the keytab file

Import-Module ActiveDirectory

Write-Host "Kerberizer and Keytab generating script"
Write-Host "---------------------------------------"

# Collect information
$realm = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name.ToString()
$realm = $realm.ToUpper()
$dc = Get-ADDomain | select-string -pattern "[a-zA-Z_]+?"
$path = 'CN=Users,' + $dc
$fqdn = Read-Host -Prompt 'FQDN of the server to kerberize'
$service_principal = "HTTP/$fqdn@$realm"
$hostname = $fqdn.Split(".") | select -First 1
Write-Host "Creating Service principal `"$service_principal`""

# Test connection to server
if(!(Test-Connection -Cn $fqdn -BufferSize 16 -Count 1 -ea 0 -quiet)){
    Throw "`n`"$fqdn`" is not reachable"
}

# Make sure this isn't an IP Address
if($fqdn -match "\d+\.\d+\.\d+\.\d+"){
    Throw "`"$fqdn`" is an IP Address and not a Fully Quallified Domain Name (FQDN)"
}

# Verify Path
$new_path = Read-Host -Prompt "`nPath to Userspace of new Kerberos principal[$path]"
if (!$new_path.equals("")){
    $path = $new_path
}

# Try to reach the given path
try {
    $path_exists = [adsi]::Exists("LDAP://$path")
} catch {
    Throw("`"$path`" is an invalid path")
}
if (!$path_exists){
    Throw("`"$path`" does not exist")
}
Write-Host "Using the path `"$path`""

# Create AD user
try {
    New-ADUser -Name $hostname -GivenName $hostname -SamAccountName $hostname -DisplayName $hostname `
    -UserPrincipalName $service_principal -Email "$hostname@cloudtest2.info" `
    -AccountPassword (ConvertTo-SecureString "Control123" -AsPlainText -force) `
        -Path "$path" -PasswordNeverExpires $True -Enabled $True
} catch {
    $response = Read-Host -Prompt "`nReplace existing Service Principal `"$hostname`"? [no]"
    if ($response -match "^(y|Y)."){
        Set-ADUser $hostname -GivenName $hostname -SamAccountName $hostname -DisplayName $hostname `
        -UserPrincipalName $service_principal -Email "$hostname@cloudtest2.info" `
        -PasswordNeverExpires $True -Enabled $True
    }
}

# Set the service principal name and verify
setspn -A HTTP/$fqdn@$realm $hostname
try {
    setspn -L $hostname
} catch {
    Throw "Unable to create Service Principal for $hostname"
}

# Verify Keytab file save location
$location = "~\Downloads"

# Save location prompt
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null 
$FolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
$FolderDialog.rootfolder = "MyComputer"
Write-Host "`nChoose the folder where you would like to save the keytab file"
$FolderDialog.ShowDialog() | Out-Null
$location = $FolderDialog.SelectedPath

# Generate keytab file
$ErrorActionPreference= 'silentlycontinue'
ktpass /out $location\$hostname.keytab /mapuser $hostname /princ $service_principal `
/pass Control123 | Out-Null 

# End script
[System.Windows.Forms.MessageBox]::Show("Finished!`nKeytab file saved successfully to $location\$hostname.keytab")
