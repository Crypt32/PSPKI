function Get-AdcsDatabaseRow {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbRow')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority[]]$CertificationAuthority,
        [SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbViewTableName]$Table = "Request",
        [Alias('ID')]
        [int[]]$RowID,
        [ValidateRange(1,2147483647)]
        [int]$Page = 1,
        [int]$PageSize = [int]::MaxValue,
        [Alias("Properties", "IncludeProperty", "IncludeProperties", "IncludedProperty", "IncludedProperties")]
        [String[]]$Property,
        [String[]]$Filter,
        [switch]$IncludeAttribute,
        [switch]$IncludeExtension
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop

        $NativeTable = if ("Revoked", "Issued", "Pending", "Failed" -contains $Table) {
            "Request"
        } else {
            $Table
        }
        $IdColumn = switch ($Table) {
            {($_ -eq "Request") `
                -or ($_ -eq "Revoked") `
                -or ($_ -eq "Issued") `
                -or ($_ -eq "Pending") `
                -or ($_ -eq "Failed")}
                        {"RequestID"}
            "Extension" {"ExtensionRequestId"}
            "Attribute" {"AttributeRequestId"}
            "CRL"       {"CRLRowId"}
        }
    }
    process {
        foreach ($CA in $CertificationAuthority) {
             try {
                $Reader = $CA.GetDbReader($Table)
                $Schema = $Reader.GetTableSchema()
            } catch {
                Write-Error $_
                continue
            } finally {
                if ($Reader -ne $null) {
                    $Reader.Dispose()
                }
            }
            if ($NativeTable -eq "Request" -or $NativeTable -eq "CRL") {
                # 'Request' and 'CRL' tables return single row item per RowID. If RowID is specified, all
                # other filters are ignored, because exact row is requested. This is by design.
                if ($RowID -ne $null) {
                    $RowID | ForEach-Object {
                        $Reader = $CA.GetDbReader($Table)
                        Get-RequestRow `
                            -CA $CA `
                            -Reader $Reader `
                            -Property $Property `
                            -Filter "$IdColumn -eq $_" `
                            -Schema $Schema `
                            -Page $Page `
                            -PageSize $PageSize `
                            -IncludeAttribute:$IncludeAttribute `
                            -IncludeExtension:$IncludeExtension
                    }
                } else {
                    $Reader = $CA.GetDbReader($Table)
                    Get-RequestRow `
                        -CA $CA `
                        -Reader $Reader `
                        -Property $Property `
                        -Filter $Filter `
                        -Schema $Schema `
                        -Page $Page `
                        -PageSize $PageSize `
                        -IncludeAttribute:$IncludeAttribute `
                        -IncludeExtension:$IncludeExtension
                }
            } else {
                # 'Extension' or 'Attribute' tables may return multiple objects for single RowID. Therefore,
                # if one of these tables is used and RowID is specified, silently append RowID filter to
                # existing filter list to allow 2nd level filtering.
                if ($RowID -ne $null) {
                    $RowID | ForEach-Object {
                        $Reader = $CA.GetDbReader($Table)
                        $LocalFilter = $Filter + "$IdColumn -eq $_"
                        Get-RequestRow `
                            -CA $CA `
                            -Reader $Reader `
                            -Property $Property `
                            -Filter $LocalFilter `
                            -Schema $Schema `
                            -Page $Page `
                            -PageSize $PageSize `
                            -IncludeAttribute:$IncludeAttribute `
                            -IncludeExtension:$IncludeExtension
                        #$Filter = $Filter[0..($Filter.Length - 2)]
                    }
                } else {
                    $Reader = $CA.GetDbReader($Table)
                    Get-RequestRow `
                        -CA $CA `
                        -Reader $Reader `
                        -Property $Property `
                        -Filter $Filter `
                        -Schema $Schema `
                        -Page $Page `
                        -PageSize $PageSize `
                        -IncludeAttribute:$IncludeAttribute `
                        -IncludeExtension:$IncludeExtension
                }
            }
        }
    }
}