function Restore-CertificateRevocationListFlagDefault {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.Flags.CRLFlag')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.Flags.CRLFlag[]]$InputObject,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($CRLFlag in $InputObject) {
            try {
                $CRLFlag.Restore()
                $Status = $CRLFlag.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Verbose ($RestartRequired -f "Certificate Revocation List settings")}
                } else {Write-Verbose $NothingIsSet}
                $CRLFlag
            } finally { }
        }
    }
}