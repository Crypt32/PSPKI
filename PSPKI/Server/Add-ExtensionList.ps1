function Add-ExtensionList {
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
                if ($EnabledExtension) {$EnabledExtension | ForEach-Object {$ExtensionList.Add("EnabledExtensionList", $_)}}
                if ($OfflineExtension) {$OfflineExtension | ForEach-Object {$ExtensionList.Add("OfflineExtensionList", $_)}}
                if ($DisabledExtension) {$DisabledExtension | ForEach-Object {$ExtensionList.Add("DisabledExtensionList", $_)}}
                $ExtensionList
            } finally { }
        }
    }
}