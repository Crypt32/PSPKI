function Restore-KeyRecoveryAgentFlagDefault {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.Flags.KRAFlag')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.Flags.KRAFlag[]]$InputObject,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($KRAFlag in $InputObject) {
            try {
                $KRAFlag.Restore()
                $Status = $KRAFlag.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "Certificate Revocation List settings")}
                } else {Write-Warning $NothingIsSet}
                $KRAFlag
            } finally { }
        }
    }
}