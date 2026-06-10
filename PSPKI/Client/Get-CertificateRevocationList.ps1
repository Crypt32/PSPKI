function Get-CertificateRevocationList {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2')]
[CmdletBinding(DefaultParameterSetName='FileName')]
    param(
        [Parameter(ParameterSetName = "FileName", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$Path,
        [Parameter(ParameterSetName = "RawData", Mandatory = $true, Position = 0)]
        [Byte[]]$RawCRL
    )
    
#region content parser
    switch ($PsCmdlet.ParameterSetName) {
        "FileName" {
            if ($(Get-Item $Path -ErrorAction Stop).PSProvider.Name -ne "FileSystem") {
                throw {"File either does not exist or not a file object"}
            }
            New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2 -ArgumentList (Resolve-Path $Path).ProviderPath
        }
        "RawData" {New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2 -ArgumentList @(,$RawCRL)}
    }
#endregion
}