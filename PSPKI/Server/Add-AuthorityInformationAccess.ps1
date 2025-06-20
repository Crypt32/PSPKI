function Add-AuthorityInformationAccess {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.AuthorityInformationAccess')]
[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.AuthorityInformationAccess[]]$InputObject,
        [Parameter(Mandatory = $true)]
        [String[]]$URI
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($AIA in $InputObject) {
            try {
                $URIs = $AIA.URI | ForEach-Object {$_.reguri}
                foreach ($url in $URI) {
                    if ($URIs -notcontains $url) {$AIA.URI += New-Object PKI.CertificateServices.AIA $url}
                }
                $AIA
            } finally { }
        }
    }
}