function Add-CAKRACertificate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.KRA')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.KRA[]]$InputObject,
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($KRA in $InputObject) {
            try {
                $KRA.Add($Certificate)
                $KRA
            } finally { }
        }
    }
}