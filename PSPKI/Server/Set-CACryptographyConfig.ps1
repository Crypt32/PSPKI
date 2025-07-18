function Set-CACryptographyConfig {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.CACryptography')]
[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.CACryptography[]]$InputObject,
        [Parameter(Position = 1)]
        [Security.Cryptography.Oid]$HashingAlgorithm,
        [Parameter(Position = 2)]
        [Security.Cryptography.Oid]$EncryptionAlgorithm,
        [switch]$AlternateSignatureAlgorithm,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($config in $InputObject) {
            try {
                if ($HashingAlgorithm) {$config.HashingAlgorithm = $HashingAlgorithm}
                if ($EncryptionAlgorithm) {$config.PublicKeyAlgorithm = $EncryptionAlgorithm}
                if ($PsBoundParameters.ContainsKey("AlternateSignatureAlgorithm")) {
                    $config.AlternateSignatureAlgorithm = $AlternateSignatureAlgorithm
                }
                $Status = $config.SetInfo($RestartCA)
                if ($Status) {
                    if (!$RestartCA) {Write-Warning ($RestartRequired -f "CA cryptography settings")}
                } else {Write-Warning $NothingIsSet}
                $config
            } finally { }
        }
    }
}