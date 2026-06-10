function Get-ObjectIdentifier {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding()]
[OutputType('System.Security.Cryptography.Oid[]')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string[]]$OIDString
    )
    process {
        $OIDString | ForEach-Object {New-Object Security.Cryptography.Oid $_}
    }
}