function Show-Certificate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('System.Security.Cryptography.X509Certificate2')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        [switch]$Multipick
    )
    begin {
        $certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    }
    process {
        [void]$certs.AddRange($Certificate)
    }
    end {
        if ($Multipick) {
            [Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
                $certs,
                "Select a certificate",
                "Select a certificate or certificates from the list",
                "MultiSelection"
            )
        }
        else {
            [Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
                $certs,
                "Select a certificate",
                "Select a certificate from the list",
                "SingleSelection"
            )
        }
    }
}