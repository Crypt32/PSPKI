function Ping-ICertInterface {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority[]]$CertificationAuthority
    )
    process {
        foreach ($CA in $CertificationAuthority) {
            New-Object psobject -Property @{
                ConfigString = $CA.ConfigString
                ICertAdmin = $CA.PingAdmin()
                ICertRequest = $CA.PingRequest()
            }
        }
    }
}