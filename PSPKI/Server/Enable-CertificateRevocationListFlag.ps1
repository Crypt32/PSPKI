function Enable-CertificateRevocationListFlag {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.Flags.CRLFlag')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.Flags.CRLFlag[]]$InputObject,
        [Parameter(Mandatory = $true)]
        [PKI.CertificateServices.Flags.CRLFlagEnum]$Flag,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($CRLFlag in $InputObject) {
            try {
                $CRLFlag.Add($Flag)
                $Status = $CRLFlag.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "Certificate Revocation List settings")}
                } else {Write-Warning $NothingIsSet}
                $CRLFlag
            } finally { }
        }
    }
}