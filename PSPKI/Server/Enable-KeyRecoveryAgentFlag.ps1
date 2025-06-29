function Enable-KeyRecoveryAgentFlag {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.Flags.KRAFlag')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.Flags.KRAFlag[]]$InputObject,
        [Parameter(Mandatory = $true)]
        [PKI.CertificateServices.Flags.KRAFlagEnum]$Flag,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($KRAFlag in $InputObject) {
            try {
                $KRAFlag.Add($Flag)
                $Status = $KRAFlag.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "Key Recovery Agent (KRA) settings")}
                } else {Write-Warning $NothingIsSet}
                $KRAFlag
            } finally { }
        }
    }
}