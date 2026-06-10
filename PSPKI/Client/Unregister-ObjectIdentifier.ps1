function Unregister-ObjectIdentifier {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding(
    ConfirmImpact = 'High',
    SupportsShouldProcess = $true
)]
    param(
        [Parameter(Mandatory = $true, ValueFrompipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.Security.Cryptography.Oid]$Value,
        [System.Security.Cryptography.OidGroup]$OidGroup = [System.Security.Cryptography.OidGroup]::All,
        [switch]$UseActiveDirectory,
        [switch]$Force
    )
    $target = if ($UseActiveDirectory) {
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.Name
        } catch {
            $Env:COMPUTERNAME
        }
    } else {
        $Env:COMPUTERNAME
    }
    if ($Force -or $PSCmdlet.ShouldProcess(
        $target,
        "Unregister object identifier with name: '$($Value.FriendlyName)' and value: '$($Value.Value)'"
    )) {
        $retValue = [SysadminsLV.PKI.Cryptography.Oid2]::Unregister($Value.Value,$OidGroup,$UseActiveDirectory)
        if (!$retValue) {
            Write-Error "An error occured while attempting to unregister specified object identifier"
        }
    }
}