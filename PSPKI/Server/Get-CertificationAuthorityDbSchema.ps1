function Get-CertificationAuthorityDbSchema {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbColumnSchema')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority[]]$CertificationAuthority,
        [SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbViewTableName]$Table = [SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbViewTableName]::Request
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($CA in $CertificationAuthority) {
            $Reader = $CA.GetDbReader($Table)
            $Reader.GetTableSchema()
        }
    }
}