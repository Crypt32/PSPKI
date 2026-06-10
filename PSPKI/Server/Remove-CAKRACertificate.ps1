function Remove-CAKRACertificate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.KRA')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.KRA[]]$InputObject,
        [String[]]$Thumbprint,
        [switch]$ShowUI,
        [switch]$InvalidOnly
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
        $Chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        [void]$Chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.4.1.311.21.6")
    }
    process {
        foreach ($KRA in $InputObject) {
            if ($KRA.Certificate.Count -ge 0) {
                if ($ShowUI) {
                        $certs = [Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
                            $KRA.Certificate,
                            "Select certificate",
                            "Select KRA certificate or certificates to remove from $($InputObject.DisplayName).",
                            "MultiSelection"
                        )
                    if ($certs -ne $null) {$certs | ForEach-Object {$KRA.Remove($_)}}
                } elseif ($InvalidOnly) {
                    $certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2[] -ArgumentList $KRA.Certificate.Count
                    $KRA.Certificate.CopyTo($certs, 0)
                    $certs | ForEach-Object {
                        if (!$Chain.Build($_)) {$KRA.Remove($_)}
                        $Chain.Reset()
                    }
                } else {
                    $Thumbprint | ForEach-Object {$KRA.Remove($_)}
                }
                $KRA
            } else {Write-Verbose "Current list of assigned key recovery agent certificates is empty!"}
        }
    }
}