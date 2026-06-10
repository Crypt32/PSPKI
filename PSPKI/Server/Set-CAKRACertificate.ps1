function Set-CAKRACertificate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.KRA')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.KRA[]]$InputObject,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
        $empty = @"
There are no any assigned KRA certificates on '{0}'.
All certificate requests that require key archival (by manually initiating key archival process or
certificate template requires key archival will fail.
"@
    }
    process {
        foreach ($KRA in $InputObject) {
            try {
                $Status = $KRA.SetInfo($RestartCA)
                if ($Status) {
                    if ($KRA.Certificate -eq $null) {Write-Warning $empty}
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "key recovery agent certificate list")}
                } else {Write-Warning $NothingIsSet}
                $KRA
            } finally { }
        }
    }
}