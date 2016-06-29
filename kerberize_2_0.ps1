# Creator: Tyler Johnson
# Date: 6/28/2016
# Name: Kerberize.ps1
# Description: Creates a kerberos service principal in AD and saves the keytab file

Import-Module ActiveDirectory
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null 
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null 

Function Custom-Dialog($title,$prompt,$button1,$button2){
    $objForm = New-Object System.Windows.Forms.Form 
    $objForm.Text = "$title"
    $objForm.ShowIcon = $False
    $objForm.Size = New-Object System.Drawing.Size(320,150) 
    $objForm.StartPosition = "CenterScreen"
    $objForm.KeyPreview = $True
    $objForm.Add_KeyDown({if($_.KeyCode -eq "Escape") {
        $objForm.Close()}})
    $objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") {
        if ($objTextBox.Text -eq $null -or $objTextBox.Text.Equals("")){
            $objTextBox.AppendText("null")}
        $objForm.Close()}})

    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(10,20) 
    $objLabel.Size = New-Object System.Drawing.Size(280,20) 
    $objLabel.Text = "$prompt"
    $objForm.Controls.Add($objLabel) 

    $objTextBox = New-Object System.Windows.Forms.TextBox 
    $objTextBox.Location = New-Object System.Drawing.Size(10,40) 
    $objTextBox.Size = New-Object System.Drawing.Size(260,20) 
    if (!$button2) {$objForm.Controls.Add($objTextBox)}

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Size(10,75)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "$button1"
    $OKButton.Add_Click({
        if ($objTextBox.Text -eq $null -or $objTextBox.Text.Equals("")){
            $objTextBox.AppendText("null")}
        $objForm.Close()})

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Size(100,75)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "$button2"
    $CancelButton.Add_Click({$objForm.Close()})

    $objForm.Controls.Add($OKButton)
    if ($button2) {$objForm.Controls.Add($CancelButton)}
    $objForm.Topmost = $True
    $objForm.Add_Shown({$objForm.Activate()})
    [void] $objForm.ShowDialog()

    return $objTextBox.Text
}

Function Browse-AD(){
    # original inspiration: https://itmicah.wordpress.com/2013/10/29/active-directory-ou-picker-in-powershell/
    # author: Rene Horn the.rhorn@gmail.com
<#
    Copyright (c) 2015, Rene Horn
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>
    $dc_hash = @{}
    $selected_ou = $null

    Import-Module ActiveDirectory
    $forest = Get-ADForest
    [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

    function Get-NodeInfo($sender, $dn_textbox)
    {
        $selected_node = $sender.Node
        $dn_textbox.Text = $selected_node.Name
    }

    function Add-ChildNodes($sender)
    {
        $expanded_node = $sender.Node

        if ($expanded_node.Name -eq "root") {
            return
        }

        $expanded_node.Nodes.Clear() | Out-Null

        $dc_hostname = $dc_hash[$($expanded_node.Name -replace '(OU=[^,]+,)*((DC=\w+,?)+)','$2')]
        $child_OUs = Get-ADObject -Server $dc_hostname -Filter 'ObjectClass -eq "organizationalUnit" -or ObjectClass -eq "container"' -SearchScope OneLevel -SearchBase $expanded_node.Name
        if($child_OUs -eq $null) {
            $sender.Cancel = $true
        } else {
            foreach($ou in $child_OUs) {
                $ou_node = New-Object Windows.Forms.TreeNode
                $ou_node.Text = $ou.Name
                $ou_node.Name = $ou.DistinguishedName
                $ou_node.Nodes.Add('') | Out-Null
                $expanded_node.Nodes.Add($ou_node) | Out-Null
            }
        }
    }

    function Add-ForestNodes($forest, [ref]$dc_hash)
    {
        $ad_root_node = New-Object Windows.Forms.TreeNode
        $ad_root_node.Text = $forest.RootDomain
        $ad_root_node.Name = "root"
        $ad_root_node.Expand()

        $i = 1
        foreach ($ad_domain in $forest.Domains) {
            Write-Progress -Activity "Querying AD forest for domains and hostnames..." -Status $ad_domain -PercentComplete ($i++ / $forest.Domains.Count * 100)
            $dc = Get-ADDomainController -Server $ad_domain
            $dn = $dc.DefaultPartition
            $dc_hash.Value.Add($dn, $dc.Hostname)
            $dc_node = New-Object Windows.Forms.TreeNode
            $dc_node.Name = $dn
            $dc_node.Text = $dc.Domain
            $dc_node.Nodes.Add("") | Out-Null
            $ad_root_node.Nodes.Add($dc_node) | Out-Null
        }
        return $ad_root_node
    }
    
    $main_dlg_box = New-Object System.Windows.Forms.Form
    $main_dlg_box.ClientSize = New-Object System.Drawing.Size(400,600)
    $main_dlg_box.Text = "Kerberos Keytab Creator: AD Browser"
    $main_dlg_box.ShowIcon = $False
    $main_dlg_box.MaximizeBox = $false
    $main_dlg_box.MinimizeBox = $false
    $main_dlg_box.FormBorderStyle = 'FixedSingle'
    $main_dlg_box.Add_KeyDown({if($_.KeyCode -eq "Escape") {
        $main_dlg_box.Close()}})

    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(10,20) 
    $objLabel.Size = New-Object System.Drawing.Size(280,20) 
    $objLabel.Text = "Choose a location for the Kerberos Principal:"
    $main_dlg_box.Controls.Add($objLabel) 

    # widget size and location variables
    $ctrl_width_col = $main_dlg_box.ClientSize.Width/20
    $ctrl_height_row = $main_dlg_box.ClientSize.Height/15
    $max_ctrl_width = $main_dlg_box.ClientSize.Width - $ctrl_width_col*2
    $max_ctrl_height = $main_dlg_box.ClientSize.Height - $ctrl_height_row
    $right_edge_x = $max_ctrl_width
    $left_edge_x = $ctrl_width_col
    $bottom_edge_y = $max_ctrl_height
    $top_edge_y = $ctrl_height_row

    # setup text box showing the distinguished name of the currently selected node
    $dn_text_box = New-Object System.Windows.Forms.TextBox
    # can not set the height for a single line text box, that's controlled by the font being used
    $dn_text_box.Width = (14 * $ctrl_width_col)
    $dn_text_box.Location = New-Object System.Drawing.Point($left_edge_x, ($bottom_edge_y - $dn_text_box.Height))
    $main_dlg_box.Controls.Add($dn_text_box)
    # /text box for dN

    # setup Ok button
    $ok_button = New-Object System.Windows.Forms.Button
    $ok_button.Size = New-Object System.Drawing.Size(($ctrl_width_col * 2), $dn_text_box.Height)
    $ok_button.Location = New-Object System.Drawing.Point(($right_edge_x - $ok_button.Width), ($bottom_edge_y - $ok_button.Height))
    $ok_button.Text = "Ok"
    $ok_button.DialogResult = 'OK'
    $main_dlg_box.Controls.Add($ok_button)
    # /Ok button

    # setup tree selector showing the domains
    $ad_tree_view = New-Object System.Windows.Forms.TreeView
    $ad_tree_view.Size = New-Object System.Drawing.Size($max_ctrl_width, ($max_ctrl_height - $dn_text_box.Height - $ctrl_height_row*1.5))
    $ad_tree_view.Location = New-Object System.Drawing.Point($left_edge_x, $top_edge_y)
    $ad_tree_view.Nodes.Add($(Add-ForestNodes $forest ([ref]$dc_hash))) | Out-Null
    $ad_tree_view.Add_BeforeExpand({Add-ChildNodes $_})
    $ad_tree_view.Add_AfterSelect({Get-NodeInfo $_ $dn_text_box})
    $main_dlg_box.Controls.Add($ad_tree_view)
    # /tree selector

    $main_dlg_box.ShowDialog() | Out-Null

    return  $dn_text_box.Text
}

# Collect information
$realm = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name.ToString()
$realm = $realm.ToUpper()

$fqdn = ""
$valid_host = $False
while(!$valid_host){
    $fqdn = Custom-Dialog "Kerberos Keytab Creator" "FQDN of the server to kerberize:" "OK"
    # If the Exit or Escape buttons were pressed, then stop the script
    if ($fqdn -eq $null -or $fqdn.Equals("")){
        Exit
    }
    if(!(Test-Connection -Cn $fqdn -BufferSize 16 -Count 1 -ea 0 -quiet)){
        [System.Windows.Forms.MessageBox]::Show(
            "`"$fqdn`" is not reachable. `nPlease enter a valid FQDN"
        )
    } else {
        if($fqdn -match "\d+\.\d+\.\d+\.\d+"){
            [System.Windows.Forms.MessageBox]::Show(
                "`"$fqdn`" is an IP Address and not a Fully Quallified Domain Name (FQDN).`nPlease enter a valid FQDN"
            )
        } else {
            $valid_host = $True
        }
    }
}

$service_principal = "HTTP/$fqdn@$realm"
$hostname = $fqdn.Split(".") | select -First 1
Write-Host "Creating Service principal `"$service_principal`""

# Find a place in Active directory
$path = ""
While ($path.Equals("") -or $path.Equals("root")){$path = Browse-AD}
Write-Host "Using the path `"$path`""

# Create AD user
try {
    New-ADUser -Name $hostname -GivenName $hostname -SamAccountName $hostname -DisplayName $hostname `
    -UserPrincipalName $service_principal -Email "$hostname@cloudtest2.info" `
    -AccountPassword (ConvertTo-SecureString "Control123" -AsPlainText -force) `
        -Path "$path" -PasswordNeverExpires $True -Enabled $True
} catch {
    $response = Custom-Dialog "Kerberos Keytab Creator" "Replace existing Service Principal `"$hostname`"?" "Yes" "No"
    # If "Yes" was clicked or "Enter" was pressed
    if ($response.Equals("null")){
        Remove-ADUser $hostname -Confirm "Yes"
        try {
            New-ADUser -Name $hostname -GivenName $hostname -SamAccountName $hostname -DisplayName $hostname `
            -UserPrincipalName $service_principal -Email "$hostname@cloudtest2.info" `
            -AccountPassword (ConvertTo-SecureString "Control123" -AsPlainText -force) `
            -Path "$path" -PasswordNeverExpires $True -Enabled $True
        } catch {
            [System.Windows.Forms.MessageBox]::Show("The Operation Failed")
            Exit
        }
    } 
}

# Set the service principal name and verify
setspn -A HTTP/$fqdn@$realm $hostname
try {
    setspn -L $hostname
} catch {
    [System.Windows.Forms.MessageBox]::Show("Unable to create Service Principal for $hostname")
    Throw "Unable to create Service Principal for $hostname"
}

# Save location prompt
$FolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
$FolderDialog.rootfolder = "MyComputer"
$FolderDialog.Description = "Location for the keytab file:"
Write-Host "`nChoose the folder where you would like to save the keytab file"
$FolderDialog.ShowDialog() | Out-Null
$location = $FolderDialog.SelectedPath

# Generate keytab file
$ErrorActionPreference= 'silentlycontinue'
ktpass /out $location\$hostname.keytab /mapuser $hostname /princ $service_principal `
/pass Control123 | Out-Null 

# End script
[System.Windows.Forms.MessageBox]::Show("Finished!`nKeytab file saved successfully to $location\$hostname.keytab")
