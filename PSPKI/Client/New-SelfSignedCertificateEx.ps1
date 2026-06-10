function New-SelfSignedCertificateEx {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('[System.Security.Cryptography.X509Certificates.X509Certificate2]')]
[CmdletBinding(DefaultParameterSetName = '__runtime')]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Subject,
        [Parameter(Position = 1)]
        [datetime]$NotBefore = [DateTime]::Now.AddDays(-1),
        [Parameter(Position = 2)]
        [datetime]$NotAfter = $NotBefore.AddDays(365),
        [string]$SerialNumber,
        [Alias('CSP')]
        [string]$ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
        [string]$AlgorithmName = "RSA",
        [int]$KeyLength = 2048,
        [validateSet("Exchange","Signature")]
        [string]$KeySpec = "Exchange",
        [Alias('EKU')]
        [Security.Cryptography.Oid[]]$EnhancedKeyUsage,
        [Alias('KU')]
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage = 0,
        [Alias('SAN')]
        [String[]]$SubjectAlternativeName,
        [bool]$IsCA,
        [int]$PathLength = -1,
        [Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,
        [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
        [string]$SignatureAlgorithm = "SHA256",
        [switch]$AlternateSignatureFormat,
        [Security.Cryptography.X509Certificates.X509Certificate2]$Issuer,
        [string]$FriendlyName,
        [Parameter(ParameterSetName = '__runtime')]
        [switch]$Runtime,
        [Parameter(ParameterSetName = '__store')]
        [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        [Parameter(Mandatory = $true, ParameterSetName = '__file')]
        [Alias('OutFile','OutPath','Out')]
        [string]$Path,
        [Parameter(Mandatory = $true, ParameterSetName = '__file')]
        [Security.SecureString]$Password,
        [switch]$AllowSMIME,
        [switch]$Exportable
    )
    $ErrorActionPreference = "Stop"
    $builder = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509CertificateBuilder

#region Fields
    if (![string]::IsNullOrEmpty($SerialNumber)) {
        if ($SerialNumber -match "[^0-9a-fA-F]") {
            throw "Serial number must be a hexadecimal string."
        }
        if ($SerialNumber.Length % 2) {$SerialNumber = "0" + $SerialNumber}
        $builder.SerialNumber = $SerialNumber
    }
    
    if ($Subject) {
        $builder.SubjectName = $Subject
    }
    $builder.NotBefore = $NotBefore
    $builder.NotAfter = $NotAfter
    $builder.HashingAlgorithm = New-Object SysadminsLV.PKI.Cryptography.Oid2 $SignatureAlgorithm, $false
    $builder.AlternateSignatureFormat = $AlternateSignatureFormat
    $builder.FriendlyName = $FriendlyName
#endregion

#region private key
    $builder.PrivateKeyInfo.ProviderName = $ProviderName
    $builder.PrivateKeyInfo.PublicKeyAlgorithm = [Security.Cryptography.Oid]$AlgorithmName
    $builder.PrivateKeyInfo.KeySpec = switch ($KeySpec) {"Exchange" {1}; "Signature" {2}}
    $builder.PrivateKeyInfo.KeyLength = $KeyLength
    $builder.PrivateKeyInfo.Exportable = $Exportable    
    switch ($PSCmdlet.ParameterSetName) {
        '__store' {
            $builder.PrivateKeyInfo.MachineContext = if ($StoreLocation -eq "LocalMachine") {$true} else {$false}
        }
        default {
            $builder.PrivateKeyInfo.MachineContext = $false
        }
    }
#endregion

#region Extensions

#region Enhanced Key Usages processing
    if ($EnhancedKeyUsage) {
        $OIDs = New-Object Security.Cryptography.OidCollection
        $EnhancedKeyUsage | ForEach-Object {
            [void]$OIDs.Add($_)
        }
        $EKU = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension $OIDs, $false
        [void]$builder.Extensions.Add($EKU)
    }
#endregion

#region Key Usages processing
    $LocalKeyUsage = $KeyUsage
    if ($PSBoundParameters.Keys.Contains("IsCA") -and $IsCA) {
        $LocalKeyUsage = $LocalKeyUsage -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        $LocalKeyUsage = $LocalKeyUsage -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign
    }
    $KU = New-Object Security.Cryptography.X509Certificates.X509KeyUsageExtension $LocalKeyUsage, $true
    [void]$builder.Extensions.Add($KU)
#endregion

#region Basic Constraints processing
    if ($PSBoundParameters.Keys.Contains("IsCA")) {
        if (!$IsCA) {$PathLength = -1}
        $critical = $IsCA
        $hasPathLengthConstraint = $PathLength -ge 0
        $BasicConstraints = New-Object Security.Cryptography.X509Certificates.X509BasicConstraintsExtension $IsCA, $hasPathLengthConstraint, $PathLength, $critical
        [void]$builder.Extensions.Add($BasicConstraints)
    }
#endregion

#region SAN processing
    if ($SubjectAlternativeName) {
        $Names = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeNameCollection
        foreach ($altname in $SubjectAlternativeName) {
            $Name = switch -Regex ($altname) {
                "^dns:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "DnsName", $Matches[1]
                }
                "^email:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "Rfc822Name", $Matches[1]
                }
                "^upn:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "UserPrincipalName", $Matches[1]
                }
                "^ip:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "IpAddress", $Matches[1]
                }
                "^dn:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "DirectoryName", $Matches[1]
                }
                "^oid:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "RegisteredId", $Matches[1]
                }
                "^url:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "URL", $Matches[1]
                }
                "^guid:(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "Guid", $Matches[1]
                }
                "other:(.+):(.+)" {
                    New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AlternativeName "OtherName", $Matches[2], $Matches[1]
                }
            }
            $Names.Add($Name)
        }
        $SAN = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509SubjectAlternativeNamesExtension $Names, $false
        [void]$builder.Extensions.Add($SAN)
    }
#endregion

if ($CustomExtension) {
    $CustomExtension | ForEach-Object {
        [void]$builder.Extensions.Add($_)
    }
}

#endregion

    $Cert = $builder.Build($Issuer)
    switch ($PSCmdlet.ParameterSetName) {
        '__store' {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store "My", $StoreLocation
            try {
                $store.Open("ReadWrite")
                $store.Add($cert)
            } finally {
                $store.Close()
            }            
        }
        '__file' {
            $pfxBytes = $Cert.Export("Pkcs12", $Password)
            Export-Binary $Path $pfxBytes
        }
    }
    $Cert
}