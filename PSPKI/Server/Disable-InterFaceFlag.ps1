function Disable-InterfaceFlag {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.Flags.InterfaceFlag')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.Flags.InterfaceFlag[]]$InputObject,
        [Parameter(Mandatory = $true)]
        [PKI.CertificateServices.Flags.InterfaceFlagEnum]$Flag,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($InterfaceFlag in $InputObject) {
            try {
                $InterfaceFlag.Remove($Flag)
                $Status = $InterfaceFlag.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "management interface settings")}
                } else {Write-Warning $NothingIsSet}
                $InterfaceFlag
            } finally { }
        }
    }
}