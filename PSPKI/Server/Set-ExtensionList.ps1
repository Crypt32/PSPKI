function Set-ExtensionList {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.PolicyModule.ExtensionList')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.PolicyModule.ExtensionList[]]$InputObject,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($ExtensionList in $InputObject) {
            try {
                $Status = $ExtensionList.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "policy module extension lists")}
                } else {Write-Warning $NothingIsSet}
                $ExtensionList
            } finally { }
        }
    }
}