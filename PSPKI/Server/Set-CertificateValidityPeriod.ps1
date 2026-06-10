function Set-CertificateValidityPeriod {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.CertValiditySetting')]
[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.CertValiditySetting[]]$InputObject,
        [Parameter(Mandatory = $true)]
        [ValidateScript({$_ -match "^\d+\shours$|days$|weeks$|months$|years$"})]
        [string]$ValidityPeriod,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($CertValidity in $InputObject) {
            try {
                $CertValidity.ValidityPeriod = $ValidityPeriod
                $Status = $CertValidity.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "certificate validity settings")}
                } else {Write-Warning $NothingIsSet}
                $CertValidity
            } finally { }
        }
    }
}