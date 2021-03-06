function Get-CryptographicServiceProvider {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Cryptography.CspProviderInfoCollection')]
[CmdletBinding()]
    param(
        [string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Name)) {
        [SysadminsLV.PKI.Cryptography.CspProviderInfoCollection]::GetProviderInfo()
    } else {
        $retValue = New-Object SysadminsLV.PKI.Cryptography.CspProviderInfoCollection
        $provider = [SysadminsLV.PKI.Cryptography.CspProviderInfoCollection]::GetProviderInfo($Name)
        if ($provider -ne $null) {
            $retValue.Add($provider)
        }
        $retValue
    }    
}