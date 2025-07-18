#region assembly import
Add-Type -Path $PSScriptRoot\Library\SysadminsLV.Asn1Parser.dll -ErrorAction Stop
Add-Type -Path $PSScriptRoot\Library\SysadminsLV.PKI.dll -ErrorAction Stop
Add-Type -Path $PSScriptRoot\Library\SysadminsLV.PKI.Win.dll -ErrorAction Stop
Add-Type -Path $PSScriptRoot\Library\SysadminsLV.PKI.OcspClient.dll -ErrorAction Stop
Add-Type -AssemblyName System.Security -ErrorAction Stop
#endregion

#region global variable section
[bool]$PsIsCore = if ($PSVersionTable.PSEdition -like "*core*") {$true} else {$false}

# compatibility
[bool]$NoDomain = $true # computer is a member of workgroup
try {
    # check if any domain controller is reachable
    [void][System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
    # then read configuration naming context path
    $Domain = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
    $PkiConfigContext = "CN=Public Key Services,CN=Services,$Domain"
    $NoDomain = $false
} catch {
    $NoDomain = $true
    Write-Warning @'
Current machine is not joined to AD DS forest. Commands that depend on Active Directory will not run.
'@
}

[bool]$NoCAPI = $true   # CertAdm.dll server managemend library is missing
if (Test-Path $PSScriptRoot\Server) {
    try {
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
        $NoCAPI = $false
    } catch {
        $NoCAPI = $true
        Write-Warning @'
Active Directory Certificate Services remote administration tools (RSAT) are not installed and only
client-side functionality will be available.
'@
    }
}


# warning messages
$RestartRequired = @"
New {0} are set, but will not be applied until Certification Authority service is restarted.
In future consider to use '-RestartCA' switch for this cmdlet to restart Certification Authority service immediatelly when new settings are set.

See more: Start-CertificationAuthority, Stop-CertificationAuthority and Restart-CertificationAuthority cmdlets.
"@
$NothingIsSet = @"
Input object was not modified since it was created. Nothing is written to the CA configuration.
"@
#endregion

#region helper functions
$PREREQ_ADDS = "ADDS"
$PREREQ_RSAT = "RSAT"
function Assert-CommandRequirement {
[CmdletBinding()]
    param([string[]]$requirement)

    # return immediately if no requirements are asked
    if (!$requirement) {
        return
    }

    $Caller = (Get-PSCallStack)[1].FunctionName -replace "\<.*"
    $result = $requirement | %{
        switch($_) {
            $PREREQ_ADDS {
                if ($NoDomain) {"'AD DS Domain Membership'"}
            }
            $PREREQ_RSAT {
                if ($NoCAPI) {"'AD CS RSAT tools'"}
            }
        }
    }

    # if '$result' is null, then all assertions are passed, good to go
    if (!$result) {
        return
    }
    # otherwise fire error
    Write-Error ("'{0}' command cannot run on this system, because it fails one or more requirements: {1}" -f $Caller, ($result -join ", "))
}

function Clear-ComObject($ComObject) {
    [SysadminsLV.PKI.Utils.CryptographyUtils]::ReleaseCom($ComObject)
}
function Export-Binary([System.IO.FileInfo]$OutPath, [byte[]]$data) {
    if ($PsIsCore) {
        Set-Content -Path $OutPath -Value $data -AsByteStream
    } else {
        Set-Content -Path $OutPath -Value $data -Encoding Byte
    }
}
function Ping-ICertAdmin ($ConfigString) {
    $success = $true
    try {
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
        $var = $CertAdmin.GetCAProperty($ConfigString,0x6,0,4,0)
    } catch {$success = $false}
    $success
}

function Write-ErrorMessage {
    param (
        [SysadminsLV.PKI.Utils.PSErrorSourceEnum]$Source,
        $ComputerName,
        $ExtendedInformation
    )
$DCUnavailable = @"
"Active Directory domain could not be contacted.
"@
$CAPIUnavailable = @"
Unable to locate required assemblies. This can be caused if attempted to run this module on a client machine where AdminPack/RSAT (Remote Server Administration Tools) are not installed.
"@
$WmiUnavailable = @"
Unable to connect to CA server '$ComputerName'. Make sure if Remote Registry service is running and you have appropriate permissions to access it.
Also this error may indicate that Windows Remote Management protocol exception is not enabled in firewall.
"@
$XchgUnavailable = @"
Unable to retrieve any 'CA Exchange' certificates from '$ComputerName'. This error may indicate that target CA server do not support key archival. All requests which require key archival will immediately fail.
"@
    switch ($source) {
        DCUnavailable {
            Write-Error -Category ObjectNotFound -ErrorId "ObjectNotFoundException" `
            -Message $DCUnavailable
        }
        CAPIUnavailable {
            Write-Error -Category NotImplemented -ErrorId "NotImplementedException" `
            -Message $NoCAPI; exit
        }
        CAUnavailable {
            Write-Error -Category ResourceUnavailable -ErrorId ResourceUnavailableException `
            -Message "Certificate Services are either stopped or unavailable on '$ComputerName'."
        }
        WmiUnavailable {
            Write-Error -Category ResourceUnavailable -ErrorId ResourceUnavailableException `
            -Message $WmiUnavailable
        }
        WmiWriteError {
            try {$text = Get-ErrorMessage $ExtendedInformation}
            catch {$text = "Unknown error '$code'"}
            Write-Error -Category NotSpecified -ErrorId NotSpecifiedException `
            -Message "An error occured during CA configuration update: $text"
        }
        ADKRAUnavailable {
            Write-Error -Category ObjectNotFound -ErrorId "ObjectNotFoundException" `
            -Message "No KRA certificates found in Active Directory."
        }
        ICertAdminUnavailable {
            Write-Error -Category ResourceUnavailable -ErrorId ResourceUnavailableException `
            -Message "Unable to connect to management interfaces on '$ComputerName'"
        }
        NoXchg {
            Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundException `
            -Message $XchgUnavailable
        }
        NonEnterprise {
            Write-Error -Category NotImplemented -ErrorAction NotImplementedException `
            -Message "Specified Certification Authority type is not supported. The CA type must be either 'Enterprise Root CA' or 'Enterprise Standalone CA'."
        }
    }
}
#endregion

#region module installation stuff
# dot-source all function files
Get-ChildItem -Path $PSScriptRoot -Include *.ps1 -Recurse | Foreach-Object { . $_.FullName }

# DS-dependent aliases
New-Alias -Name Add-AdCrl                   -Value Add-AdCertificateRevocationList -Force
New-Alias -Name Remove-AdCrl                -Value Remove-AdCertificateRevocationList -Force
New-Alias -Name Get-CA                      -Value Get-CertificationAuthority -Force
New-Alias -Name Get-KRAFlag                 -Value Get-KeyRecoveryAgentFlag -Force
New-Alias -Name Enable-KRAFlag              -Value Enable-KeyRecoveryAgentFlag -Force
New-Alias -Name Disable-KRAFlag             -Value Disable-KeyRecoveryAgentFlag -Force
New-Alias -Name Restore-KRAFlagDefault      -Value Restore-KeyRecoveryAgentFlagDefault -Force
New-Alias -Name Connect-CA                  -Value Connect-CertificationAuthority -Force

# RSAT-dependent aliases
New-Alias -Name Add-AIA                     -Value Add-AuthorityInformationAccess -Force
New-Alias -Name Get-AIA                     -Value Get-AuthorityInformationAccess -Force
New-Alias -Name Remove-AIA                  -Value Remove-AuthorityInformationAccess -Force
New-Alias -Name Set-AIA                     -Value Set-AuthorityInformationAccess -Force

New-Alias -Name Add-CDP                     -Value Add-CRLDistributionPoint -Force
New-Alias -Name Get-CDP                     -Value Get-CRLDistributionPoint -Force
New-Alias -Name Remove-CDP                  -Value Remove-CRLDistributionPoint -Force
New-Alias -Name Set-CDP                     -Value Set-CRLDistributionPoint -Force
    
New-Alias -Name Get-CRLFlag                 -Value Get-CertificateRevocationListFlag -Force
New-Alias -Name Enable-CRLFlag              -Value Enable-CertificateRevocationListFlag -Force
New-Alias -Name Disable-CRLFlag             -Value Disable-CertificateRevocationListFlag -Force
New-Alias -Name Restore-CRLFlagDefault      -Value Restore-CertificateRevocationListFlagDefault -Force
    
New-Alias -Name Remove-Request              -Value Remove-AdcsDatabaseRow -Force
    
New-Alias -Name Get-CAACL                   -Value Get-CertificationAuthorityAcl -Force
New-Alias -Name Add-CAACL                   -Value Add-CertificationAuthorityAcl -Force
New-Alias -Name Remove-CAACL                -Value Remove-CertificationAuthorityAcl -Force
New-Alias -Name Set-CAACL                   -Value Set-CertificationAuthorityAcl -Force

New-Alias -Name Get-OCSPACL                 -Value Get-OnlineResponderAcl -Force
New-Alias -Name Add-OCSPACL                 -Value Add-OnlineResponderAcl -Force
New-Alias -Name Remove-OCSPACL              -Value Remove-OnlineResponderAcl -Force
New-Alias -Name Set-OCSPACL                 -Value Set-OnlineResponderAcl -Force

# compat/rename aliases
New-Alias -Name Get-CASecurityDescriptor    -Value Get-CertificationAuthorityAcl -Force
New-Alias -Name Set-CASecurityDescriptor    -Value Set-CertificationAuthorityAcl -Force
New-Alias -Name Add-CAAccessControlEntry    -Value Add-CertificationAuthorityAcl -Force
New-Alias -Name Remove-CAAccessControlEntry -Value Remove-CertificationAuthorityAcl -Force

New-Alias -Name oid                         -Value Get-ObjectIdentifier -Force
New-Alias -Name oid2                        -Value Get-ObjectIdentifierEx -Force
New-Alias -Name Get-Csp                     -Value Get-CryptographicServiceProvider -Force
New-Alias -Name Get-CRL                     -Value Get-CertificateRevocationList -Force
New-Alias -Name Show-CRL                    -Value Show-CertificateRevocationList -Force
New-Alias -Name Get-CTL                     -Value Get-CertificateTrustList -Force
New-Alias -Name Show-CTL                    -Value Show-CertificateTrustList -Force

# define restricted functions
$RestrictedFunctions = "Get-RequestRow",
                       "Ping-ICertAdmin",
                       "Write-ErrorMessage",
                       "Clear-ComObject",
                       "Export-Binary"
# do not export any function from Server folder when RSAT is not installed.
# only client components are exported
if ($NoCAPI) {
    $RestrictedFunctions += Get-ChildItem $PSScriptRoot\Server -Filter "*.ps1" | ForEach-Object {$_.BaseName}
    
}
# dot-source all functions except restricted ones
Get-ChildItem $PSScriptRoot -Include *.ps1 -Recurse | `
    ForEach-Object {$_.Name -replace ".ps1"} | `
    Where-Object {$RestrictedFunctions -notcontains $_}
#endregion

# conditional type data
if ($PSVersionTable.PSVersion.Major -eq 5) {
    Update-TypeData -AppendPath $PSScriptRoot\Types\PSPKI.PS5Types.ps1xml
}