function Get-ObjectIdentifierEx {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Cryptography.Oid2[]')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Security.Cryptography.OidGroup]$Group,
        [switch]$UseActiveDirectory
    )
    if ($Group -eq $null) {
        [SysadminsLV.PKI.Cryptography.Oid2]::GetAllOids($Value,$UseActiveDirectory)
    } else {
        @(New-Object SysadminsLV.PKI.Cryptography.Oid2 -ArgumentList $Value, $Group, $UseActiveDirectory)
    }
    
}