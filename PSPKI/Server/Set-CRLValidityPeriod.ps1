function Set-CRLValidityPeriod {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.CRLValiditySetting')]
[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.CRLValiditySetting[]]$InputObject,
        [Parameter(Position = 1)]
        [ValidateScript({$_ -match "\d+ hours$|days$|weeks$|months$|years$"})]
        [string]$BaseCRL,
        [Parameter(Position = 2)]
        [ValidateScript({$_ -match "\d+ hours$|days$|weeks$|months$|years$"})]
        [string]$BaseCRLOverlap,
        [Parameter(Position = 3)]
        [ValidateScript({$_ -match "\d+ hours$|days$|weeks$|months$|years$"})]
        [string]$DeltaCRL,
        [Parameter(Position = 4)]
        [ValidateScript({$_ -match "\d+ hours$|days$|weeks$|months$|years$"})]
        [string]$DeltaCRLOverlap,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($CRLValidity in $InputObject) {
            try {
                if ($BaseCRL) {$CRLValidity.BaseCRL = $BaseCRL}
                if ($BaseCRLOverlap) {$CRLValidity.BaseCRLOverlap = $BaseCRLOverlap}
                if ($DeltaCRL) {$CRLValidity.DeltaCRL = $DeltaCRL}
                if ($DeltaCRLOverlap) {$CRLValidity.DeltaCRLOverlap = $DeltaCRLOverlap}
                $Status = $CRLValidity.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "CRL validity settings")}
                } else {Write-Warning $NothingIsSet}
                $CRLValidity
            } finally { }
        }
    }
}