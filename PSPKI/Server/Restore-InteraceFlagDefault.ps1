function Restore-InterfaceFlagDefault {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.Flags.InterfaceFlag')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.Flags.InterfaceFlag[]]$InputObject,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($InterfaceFlag in $InputObject) {
            try {
                $InterfaceFlag.Restore()
                $Status = $InterfaceFlag.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "management interface settings")}
                } else {Write-Warning $NothingIsSet}
                $InterfaceFlag
            } finally { }
        }
    }
}