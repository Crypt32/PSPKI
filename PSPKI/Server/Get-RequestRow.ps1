function Get-RequestRow {
[CmdletBinding()]
    param(
        [PKI.CertificateServices.CertificateAuthority]$CA,
        [SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbReader]$Reader,
        [int]$Page,
        [int]$PageSize = [int]::MaxValue,
        [String[]]$Property,
        [String[]]$Filter,
        [SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbColumnSchema[]]$Schema,
        [switch]$IncludeAttribute,
        [switch]$IncludeExtension
    )
    $ErrorActionPreference = "Stop"
    $AllowedIncludeSourceTables = @("Request", "Revoked", "Issued", "Pending", "Failed")
    $AllowIncludeAttribute = $AllowedIncludeSourceTables -contains $Reader.ViewTable -and $IncludeAttribute
    $AllowIncludeExtension = $AllowedIncludeSourceTables -contains $Reader.ViewTable -and $IncludeExtension

    function Join-AttributeTable($DbRow) {
        $NestedReader = $CA.GetDbReader("Attribute")
        [void]$NestedReader.AddQueryFilter(
            (New-Object SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbQueryFilter "AttributeRequestId", 1, $DbRow.Properties["RequestID"])
        )
        $Rows = $NestedReader.GetView() | ForEach-Object {
            New-Object PSObject -Property @{
                AttributeName = $_.Properties["AttributeName"]
                AttributeValue = $_.Properties["AttributeValue"]
            }
        }
        $DbRow.Properties.Add("RowAttributes", $Rows)
    }
    function Join-ExtensionTable($DbRow) {
        $NestedReader = $CA.GetDbReader("Extension")
        [void]$NestedReader.AddQueryFilter(
            (New-Object SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbQueryFilter "ExtensionRequestId", 1, $DbRow.Properties["RequestID"])
        )
        $Rows = $NestedReader.GetView() | ForEach-Object {
            New-Object PSObject -Property @{
                ExtensionNameOid = $_.Properties["ExtensionNameOid"]
                ExtensionObject = $_.Properties["ExtensionObject"]
                ExtensionFlags = $_.Properties["ExtensionFlagsEnum"]
            }
        }
        $DbRow.Properties.Add("RowExtensions", $Rows)
    }
    
    # parse restriction filters
    if ($Filter -ne $null) {
        foreach ($line in $Filter) {
            if ($line -notmatch "^(.+)\s(-eq|-lt|-le|-ge|-gt)\s(.+)$") {
                $Reader.Dispose()
                throw "Malformed filter: '$line'"
            }
            $Seek = switch ($matches[2]) {
                "-eq" {1}
                "-lt" {2}
                "-le" {4}
                "-ge" {8}
                "-gt" {16}
            }
            $Value = $matches[3]
            $SchemaRow = $Schema | Where-Object {$_.Name -eq $matches[1]}
            if ($SchemaRow -eq $null) {
                throw "Specified column '$($matches[1])' is not found."
            }
            $Value = switch ($SchemaRow.DataType) {
                "Long"     {$matches[3] -as [int]}
                "DateTime" {[DateTime]::ParseExact($matches[3],"MM/dd/yyyy HH:mm:ss",[Globalization.CultureInfo]::InvariantCulture)}
                default    {$matches[3]}
            }
            if ($matches[1] -eq "CertificateTemplate") {
                if ($Value -ne "Machine") {
                    $Value = ([Security.Cryptography.Oid]$Value).Value
                }
            }
            $f = New-Object SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbQueryFilter $SchemaRow.Name, $Seek, $Value
            [void]$Reader.AddQueryFilter($f)
        }
    }

    #set output columns
    $Property | Where-Object {$_} | ForEach-Object {
        [void]$Reader.AddColumnToView($_)
    }
    try {
        $skip = ($Page - 1) * $PageSize
        $Reader.GetView($skip, $PageSize) | ForEach-Object {
            if ($AllowIncludeAttribute) {
                Join-AttributeTable $_
            }
            if ($AllowIncludeExtension) {
                Join-ExtensionTable $_
            }

            foreach ($key in $_.Properties.Keys) {
                $_ | Add-Member -MemberType NoteProperty $key -Value $_.Properties[$key] -Force
            }
            Write-Output $_
        }
    } finally {
        $Reader.Dispose()
    }
}