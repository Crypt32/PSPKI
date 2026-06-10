function Get-CAExchangeCertificate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType(
    'System.String[]',
    'System.Byte[]',
    'System.Security.Cryptography.X509Certificates.X509Certificate2'
)]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority[]]$CertificationAuthority,
        [SysadminsLV.Asn1Parser.EncodingType]$Encoding = "Base64Header",
        [switch]$X509
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($CA in $CertificationAuthority) {
            $xchg = $CA.GetCAExchangeCertificate()
            if ($X509) {return $xchg}
            switch ($Encoding) {
                "Base64Header" {[SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($xchg.RawData,"Base64Header")}
                "Base64" {[SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($xchg.RawData,"Base64")}
                "Binary" {$xchg.RawData}
                default {Write-Error "Specified encoding type is not supported."; return}
            }
        }
    }
}