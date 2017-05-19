# Simple OU/Group/User creation
$puzzle_ou = "OU=Puzzle,OU=IFA,DC=Example,DC=com"
$user_ou   = "OU=Users,OU=Puzzle,OU=IFA,DC=Example,DC=com"
$group_ou  = "OU=Groups,OU=Puzzle,OU=IFA,DC=Example,DC=com"


New-ADOrganizationalUnit -Name "Puzzle" -Path "OU=IFA,DC=Example,DC=com" -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Users" -Path $puzzle_ou -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Groups" -Path $puzzle_ou -ProtectedFromAccidentalDeletion $true
New-ADOrganizationalUnit -Name "Workstations" -Path $puzzle_ou -ProtectedFromAccidentalDeletion $true


# Create User
New-ADUser -Name "Max Muster"`
    -Surname "Muster"`
    -GivenName "Max"`
    -DisplayName "Max Muster"`
    -SamAccountName "mmuster"`
    -UserPrincipalName "mmuster"`
    -Path $user_ou


# AD group creation
New-ADGroup -Name "SYS-E-Developer"`
    -GroupCategory Security `
    -GroupScope Global `
    -Path $group_ou


New-ADGroup -Name "DEV-E-Developer"`
    -GroupCategory Security `
    -GroupScope DomainLocal `
    -Path $group_ou


New-ADGroup -Name "BAC-M-Office"`
    -GroupCategory Security `
    -GroupScope DomainLocal `
    -Path $group_ou


# Add user to Group
Add-ADGroupMember "SYS-E-Developer" "mmuster"


# create users from csv-file
$Users = Import-Csv -Delimiter "," -Path "C:\Users\Administrator\Documents\ad_user.csv"


foreach ($Users in $Users){
    $Displayname = $Users.Firstname + " " + $Users.Lastname
    $Firstname   = $Users.Firstname
    $Lastname    = $Users.Lastname
    $OU          = "OU=Users,OU=Puzzle,OU=IFA,DC=Example,DC=ch"
    $SAM         = $Users.SAM
    $UPN         = $Users.SAM + "@" + "example.com"
    $Description = $Users.Description
    $Password    = "ChangeMe"    
    New-ADUser -Name "$Displayname"`
        -DisplayName "$Displayname"`
        -SamAccountName $SAM `
        -UserPrincipalName $UPN `
        -GivenName "$UserFirstname" `
        -Surname "$UserLastname" `
        -Description "$Description" `
        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force)`
        -Enabled $true `
        -Path "$OU" `
        -ChangePasswordAtLogon $false `
        –PasswordNeverExpires $true
}

# Show created Users
Get-ADUser -Filter * -SearchBase $user_ou
