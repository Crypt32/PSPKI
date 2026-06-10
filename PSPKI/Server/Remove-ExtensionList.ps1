function Remove-ExtensionList {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.PolicyModule.ExtensionList')]
[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateServices.PolicyModule.ExtensionList[]]$InputObject,
        [Security.Cryptography.Oid[]]$EnabledExtension,
        [Alias('UserExtension')]
        [Security.Cryptography.Oid[]]$OfflineExtension,
        [Security.Cryptography.Oid[]]$DisabledExtension
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($ExtensionList in $InputObject) {
            try {
                if ($EnabledExtension) {$EnabledExtension | ForEach-Object {$ExtensionList.Remove("EnabledExtensionList", $_)}}
                if ($OfflineExtension) {$OfflineExtension | ForEach-Object {$ExtensionList.Remove("OfflineExtensionList", $_)}}
                if ($DisabledExtension) {$DisabledExtension | ForEach-Object {$ExtensionList.Remove("DisabledExtensionList", $_)}}
                $ExtensionList
            } finally { }
        }
    }
}