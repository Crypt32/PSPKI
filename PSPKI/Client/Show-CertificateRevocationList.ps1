function Show-CertificateRevocationList {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Security.Cryptography.X509Certificates.X509CRL2]$CRL
    )
    
    process {
        $CRL.ShowUI()
    }
}