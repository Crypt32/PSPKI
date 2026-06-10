function Restore-PolicyModuleFlagDefault {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.PolicyModule.EditFlag')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.PolicyModule.EditFlag[]]$InputObject,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($EditFlag in $InputObject) {
            try {
                $EditFlag.Restore()
                $Status = $EditFlag.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "Policy Module settings")}
                } else {Write-Warning $NothingIsSet}
                $EditFlag
            } finally { }
        }
    }
}