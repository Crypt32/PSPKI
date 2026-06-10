function Convert-PemToPfx {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('[System.Security.Cryptography.X509Certificates.X509Certificate2]')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('CertificatePath', 'CertPath')]
        [string]$InputPath,
        [string]$KeyPath,
        [string]$OutputPath,
        [SysadminsLV.PKI.Cryptography.X509Certificates.X509KeySpecFlags]$KeySpec = "AT_KEYEXCHANGE",
        [Security.SecureString]$Password,
        [string]$ProviderName = "Microsoft Software Key Storage Provider",
        [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
        [switch]$Install
    )
    if ($PSBoundParameters["Verbose"]) {$VerbosePreference = "continue"}
    if ($PSBoundParameters["Debug"]) {$DebugPreference = "continue"}
    $ErrorActionPreference = "Stop"

    # PSCore needs extra assembly import
    if ($PsIsCore) {
        Add-Type -AssemblyName "System.Security.Cryptography.X509Certificates"
    }

    # global variables
    Write-Verbose "Determining key storage flags..."
    $KeyStorageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    if ($Install) {
        if ($StoreLocation -eq "CurrentUser") {
            $KeyStorageFlags = $KeyStorageFlags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
        } else {
            $KeyStorageFlags = $KeyStorageFlags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
        }
    } else {
        $KeyStorageFlags = $KeyStorageFlags -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    }
    Write-Verbose "Resulting storage flags: $KeyStorageFlags"

    $script:AlgFamily = ""
    [System.Collections.Generic.List[object]]$Disposables = @()

    # returns: X509Certificate2
    function __extractCert([string]$Text) {
        Write-Verbose "Reading certificate.."
        if ($Text -match "(?msx).*-{5}BEGIN\sCERTIFICATE-{5}(.+)-{5}END\sCERTIFICATE-{5}") {
            $CertRawData = [Convert]::FromBase64String($matches[1])
            $Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$CertRawData)
            Write-Verbose "Public key algorithm: $($Cert.PublicKey.Oid.FriendlyName) ($($Cert.PublicKey.Oid.Value))"
            switch ($Cert.PublicKey.Oid.Value) {
                $([SysadminsLV.PKI.Cryptography.AlgorithmOid]::RSA) { $script:AlgFamily = "RSA" }
                $([SysadminsLV.PKI.Cryptography.AlgorithmOid]::ECC) { $script:AlgFamily = "ECC" }
            }

            $Cert
        } else {
            throw "Missing certificate file."
        }
    }
    # returns: AsymmetricKey (RSACng or ECDsaCng)
    function __extractPrivateKey([string]$Text) {
        Write-Verbose "Reading private key..."
        $bin = if ($Text -match "(?msx).*-{5}BEGIN\sPRIVATE\sKEY-{5}(.+)-{5}END\sPRIVATE\sKEY-{5}") {
            Write-Verbose "Found private key in PKCS#8 format."
            [convert]::FromBase64String($matches[1])
        } elseif ($Text -match "(?msx).*-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}(.+)-{5}END\sRSA\sPRIVATE\sKEY-{5}") {
            Write-Verbose "Found RSA private key in PKCS#1 format."
            [convert]::FromBase64String($matches[1])
        }  else {
            throw "The data is invalid."
        }
        if ($AlgFamily -eq "RSA") {
            Write-Verbose "Converting RSA PKCS#1 to PKCS#8..."
            # RSA can be in PKCS#1 format, which is not supported by CngKey.
            $rsa = New-Object SysadminsLV.PKI.Cryptography.RsaPrivateKey (,$bin)
            $bin = $rsa.Export("Pkcs8")
            $rsa.Dispose()
        }

        Write-Verbose "Using provider: $ProviderName"
        $prov = [System.Security.Cryptography.CngProvider]::new($ProviderName)
        $blobType = [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob
        # make it exportable
        $cngProp = New-Object System.Security.Cryptography.CngProperty("Export Policy", [BitConverter]::GetBytes(3), "None")
        $cng = [System.Security.Cryptography.CngKey]::Import($bin, $blobType, $prov)
        $Disposables.Add($cng)
        $cng.SetProperty($cngProp)

        switch ($AlgFamily) {
            "RSA" {
                New-Object System.Security.Cryptography.RSACng $cng
            }
            "ECC" {
                New-Object System.Security.Cryptography.ECDsaCng $cng
                
            }
            default {
                throw "Specified algorithm is not supported"
            }
        }
    }
    # returns: X509Certificate2 with associated private key
    function __associatePrivateKey($Cert, $AsymmetricKey) {
        Write-Verbose "Merging public certificate with private key..."
        switch ($AlgFamily) {
            "RSA" {
                if ($csp.IsLegacy) {
                    $NewCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$Cert.RawData)
                    $cspParams = New-Object System.Security.Cryptography.CspParameters $csp.Type, $ProviderName, ("pspki-" + [guid]::NewGuid())
                    $cspParams.KeyNumber = [int]$KeySpec
                    if ($Install) {
                        if ($StoreLocation -eq "LocalMachine") {
                            $cspParams.Flags = 1
                        }
                    } else {
                        #$cspParams.Flags = 128
                    }
                    $legacyRsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider $cspParams
                    $legacyRsa.ImportParameters($AsymmetricKey.ExportParameters($true))
                    $NewCert.PrivateKey = $legacyRsa

                    $NewCert
                } else {
                    [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($Cert, $AsymmetricKey)
                }
            }
            "ECC" {[System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($Cert, $AsymmetricKey)}
        }
        Write-Verbose "Public certificate and private key are successfully merged."
    }

    function __duplicateCertWithKey($CertWithKey) {
        $PfxBytes = $CertWithKey.Export("pfx")
        New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $PfxBytes, "", $KeyStorageFlags
    }
    function __installCert($CertWithKey) {
        if (!$Install) {
            $CertWithKey
            return
        }

        Write-Verbose "Installing certificate to certificate store: $StoreLocation"
        # $CertWithKey cert has ephemeral key which cannot be installed into cert store as is.
        # so export it into PFX in memory and re-import back with storage flags
        $NewCert = __duplicateCertWithKey $CertWithKey
        # dispose ephemeral cert received from params, we have a persisted cert to return
        $CertWithKey.Dispose()

        $store = New-Object Security.Cryptography.X509Certificates.X509Store "my", $StoreLocation
        $store.Open("ReadWrite")
        $Disposables.Add($store)
        $store.Add($NewCert)
        $store.Close()
        Write-Verbose "Certificate is installed."
        # dispose this temporary cert
        $NewCert
    }
    function __exportPfx($CertWithKey) {
        if ([string]::IsNullOrWhiteSpace($OutputPath)) {
            return
        }
        Write-Verbose "Saving PFX to a file: $OutputPath"
        if (!$Password) {
            $Password = Read-Host -Prompt "Enter PFX password" -AsSecureString
        }
        $pfxBytes = $CertWithKey.Export("pfx", $Password)
        Export-Binary $OutputPath $pfxBytes
        Write-Verbose "PFX is saved."
    }

    # Determine CSP
    $csp = Get-CryptographicServiceProvider -Name $ProviderName
    if (!$csp) {
        throw "Specified provider name is invalid."
    }

    # parse content
    $Text = Get-Content -Path $InputPath -Raw -ErrorAction Stop
    Write-Debug "Extracting certificate information..."
    $Cert = __extractCert $Text
    if ($KeyPath) {
        $Text = Get-Content -Path $KeyPath -Raw -ErrorAction Stop
    }
    $PrivateKey = __extractPrivateKey $Text
    $Disposables.Add($PrivateKey)

    $PfxCert = __associatePrivateKey $Cert $PrivateKey
    __exportPfx $PfxCert
    $PfxCert = __installCert $PfxCert
    # release unmanaged resources
    $Disposables | %{$_.Dispose()}

    $PfxCert
}