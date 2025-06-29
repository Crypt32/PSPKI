function Get-ADKRACertificate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('System.Security.Cryptography.X509Certificates.X509Certificate2Collection')]
[CmdletBinding()]
    param(
        [string]$Subject,
        [string]$Issuer,
        [switch]$ValidOnly,
        [switch]$ShowUI
    )
    Assert-CommandRequirement $PREREQ_ADDS, $PREREQ_RSAT -ErrorAction Stop

    $Chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    [void]$Chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.4.1.311.21.6")
    $certs = [SysadminsLV.PKI.Management.ActiveDirectory.DsPkiCertContainer]::GetAdPkiContainer("KRA").Certificates | ForEach-Object {$_.Certificate}
    if ($certs.Length -gt 0) {
        if ($Subject) {$certs = $certs | Where-Object {$_.Subject -like $Subject}}
        if ($Issuer) {$certs = $certs | Where-Object {$_.Issuer -like $Issuer}}
        if ($ValidOnly) {
            $certs = $certs | Where-Object {
                $Chain.Build($_)
                $Chain.Reset()
            }
        }
        if ($ShowUI -and @($certs).Count -ne 0) {
            $certs = Show-Certificate $certs -Multipick
        }
        [Security.Cryptography.X509Certificates.X509Certificate2[]]$certs
    } else {Write-ErrorMessage -Source ADKRAUnavailable}
}