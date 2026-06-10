function Get-ErrorMessage {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('System.String')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$ErrorCode
    )
    [SysadminsLV.PKI.Utils.ErrorHelper]::GetMessage($ErrorCode)
}