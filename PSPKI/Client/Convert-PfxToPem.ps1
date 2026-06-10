function Convert-PfxToPem {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding(DefaultParameterSetName = '__pfxfile')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = '__pfxfile', Position = 0)]
        [IO.FileInfo]$InputFile,
        [Parameter(Mandatory = $true, ParameterSetName = '__cert', Position = 0)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true, ParameterSetName = '__pfxfile', Position = 1)]
        [Security.SecureString]$Password,
        [Parameter(Mandatory = $true, Position = 2)]
        [IO.FileInfo]$OutputFile,
        [Parameter(Position = 3)]
        [ValidateSet("Pkcs1","Pkcs8")]
        [string]$OutputType = "Pkcs8",
        [switch]$IncludeChain
    )
$signature = @"
[DllImport("crypt32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptAcquireCertificatePrivateKey(
    IntPtr pCert,
    uint dwFlags,
    IntPtr pvReserved,
    ref IntPtr phCryptProv,
    ref uint pdwKeySpec,
    ref bool pfCallerFreeProv
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptGetUserKey(
    IntPtr hProv,
    uint dwKeySpec,
    ref IntPtr phUserKey
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptExportKey(
    IntPtr hKey,
    IntPtr hExpKey,
    uint dwBlobType,
    uint dwFlags,
    byte[] pbData,
    ref uint pdwDataLen
);
[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern bool CryptDestroyKey(
    IntPtr hKey
);
[DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool PFXIsPFXBlob(
    CRYPTOAPI_BLOB pPFX
);
[DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern bool PFXVerifyPassword(
    CRYPTOAPI_BLOB pPFX,
    [MarshalAs(UnmanagedType.LPWStr)]
    string szPassword,
    int dwFlags
);
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct CRYPTOAPI_BLOB {
    public int cbData;
    public IntPtr pbData;
}
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct PUBKEYBLOBHEADERS {
    public byte bType;
    public byte bVersion;
    public short reserved;
    public uint aiKeyAlg;
    public uint magic;
    public uint bitlen;
    public uint pubexp;
 }
"@
    Add-Type -MemberDefinition $signature -Namespace PKI -Name PfxTools
#region helper functions
    function Encode-Integer ([Byte[]]$RawData) {
        # since CryptoAPI is little-endian by nature, we have to change byte ordering
        # to big-endian.
        [array]::Reverse($RawData)
        # if high byte contains more than 7 bits, an extra zero byte is added
        if ($RawData[0] -ge 128) {$RawData = ,0 + $RawData}
        [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($RawData, 2)
    }
#endregion

#region parameterset processing
    switch ($PsCmdlet.ParameterSetName) {
        "__pfxfile" {
            $bytes = [IO.File]::ReadAllBytes($InputFile)
            $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
            [Runtime.InteropServices.Marshal]::Copy($bytes,0,$ptr,$bytes.Length)
            $pfx = New-Object PKI.PfxTools+CRYPTOAPI_BLOB -Property @{
                cbData = $bytes.Length;
                pbData = $ptr
            }
            # just check whether input file is valid PKCS#12/PFX file.
            if ([PKI.PfxTools]::PFXIsPFXBlob($pfx)) {
                $certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
                try {
                    $certs.Import(
                        $bytes,
                        [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
                        "Exportable"
                    )
                    $Certificate = ($certs | Where-Object {$_.HasPrivateKey})[0]
                } catch {
                    throw $_
                    return
                } finally {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
                    Remove-Variable bytes, ptr, pfx -Force
                }
            } else {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
                Remove-Variable bytes, ptr, pfx -Force
                Write-Error -Category InvalidData -Message "Input file is not valid PKCS#12/PFX file." -ErrorAction Stop
            }
        }
        "__cert" {
            if (!$Certificate.HasPrivateKey) {
                Write-Error -Category InvalidOperation -Message "Specified certificate object does not contain associated private key." -ErrorAction Stop
            }
        }
    }
#endregion

#region constants
    $CRYPT_ACQUIRE_SILENT_FLAG = 0x40
    $PRIVATEKEYBLOB            = 0x7
    $CRYPT_OAEP                = 0x40
#endregion

#region private key export routine
    $phCryptProv = [IntPtr]::Zero
    $pdwKeySpec = 0
    $pfCallerFreeProv = $false
    # attempt to acquire private key container
    if (![PKI.PfxTools]::CryptAcquireCertificatePrivateKey($Certificate.Handle,$CRYPT_ACQUIRE_SILENT_FLAG,0,[ref]$phCryptProv,[ref]$pdwKeySpec,[ref]$pfCallerFreeProv)) {
        throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
        return
    }
    $phUserKey = [IntPtr]::Zero
    # attempt to acquire private key handle
    if (![PKI.PfxTools]::CryptGetUserKey($phCryptProv,$pdwKeySpec,[ref]$phUserKey)) {
        throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
        return
    }
    $pdwDataLen = 0
    # attempt to export private key. This method fails if certificate has non-exportable private key.
    if (![PKI.PfxTools]::CryptExportKey($phUserKey,0,$PRIVATEKEYBLOB,$CRYPT_OAEP,$null,[ref]$pdwDataLen)) {
        throw New-Object ComponentModel.Win32Exception ([Runtime.InteropServices.Marshal]::GetLastWin32Error())
        return
    }
    $pbytes = New-Object byte[] -ArgumentList $pdwDataLen
    [void][PKI.PfxTools]::CryptExportKey($phUserKey,0,$PRIVATEKEYBLOB,$CRYPT_OAEP,$pbytes,[ref]$pdwDataLen)
    # release private key handle
    [void][PKI.PfxTools]::CryptDestroyKey($phUserKey)
#endregion

#region private key blob splitter
    # extracting private key blob header.
    $headerblob = $pbytes[0..19]
    # extracting actual private key data exluding header.
    $keyblob = $pbytes[20..($pbytes.Length - 1)]
    Remove-Variable pbytes -Force
    # public key structure header has fixed length: 20 bytes: http://msdn.microsoft.com/en-us/library/aa387689(VS.85).aspx
    # copy header information to unmanaged memory and copy it to structure.
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal(20)
    [Runtime.InteropServices.Marshal]::Copy($headerblob,0,$ptr,20)
    $header = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr,[Type][PKI.PfxTools+PUBKEYBLOBHEADERS])
    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    # extract public exponent from blob header and convert it to a byte array
    $pubExponentHex = "{0:x2}" -f $header.pubexp
    if ($pubExponentHex.Length % 2) {$pubExponentHex = "0" + $pubExponentHex}
    $publicExponent = $pubExponentHex -split "([a-f0-9]{2})" | Where-Object {$_} | ForEach-Object {[Convert]::ToByte($_,16)}
    # this object is created to reduce code size. This object has properties, where each property represents
    # a part (component) of the private key and property value contains private key component length.
    # 8 means that the length of the component is KeyLength / 8. Resulting length is measured in bytes.
    # for details see private key structure description: http://msdn.microsoft.com/en-us/library/aa387689(VS.85).aspx
    $obj = New-Object psobject -Property @{
        modulus = 8; privateExponent = 8;
        prime1 = 16; prime2 = 16; exponent1 = 16; exponent2 = 16; coefficient = 16;
    }
    $offset = 0
    # I pass variable names (each name represents the component of the private key) to foreach loop
    # in the order as they follow in the private key structure and parse private key for
    # appropriate offsets and write component information to variable.
    "modulus","prime1","prime2","exponent1","exponent2","coefficient","privateExponent" | ForEach-Object {
        Set-Variable -Name $_ -Value ($keyblob[$offset..($offset + $header.bitlen / $obj.$_ - 1)])
        $offset = $offset + $header.bitlen / $obj.$_
    }
    # PKCS#1/PKCS#8 uses slightly different component order, therefore I reorder private key
    # components and pass them to a simplified ASN encoder.
    $asnblob = Encode-Integer 0
    $asnblob += "modulus","publicExponent","privateExponent","prime1","prime2","exponent1","exponent2","coefficient" | ForEach-Object {
        Encode-Integer (Get-Variable -Name $_).Value
    }
    # remove unused variables
    Remove-Variable modulus,publicExponent,privateExponent,prime1,prime2,exponent1,exponent2,coefficient -Force
    # encode resulting set of INTEGERs to a SEQUENCE
    $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 48)
    # $out variable just holds output file. The file will contain private key and public certificate
    # each will be enclosed with header and footer.
    $out = New-Object Text.StringBuilder
    if ($OutputType -eq "Pkcs8") {
        $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 4)
        $algid = [Security.Cryptography.CryptoConfig]::EncodeOID("1.2.840.113549.1.1.1") + 5,0
        $algid = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($algid, 48)
        $asnblob = 2,1,0 + $algid + $asnblob
        $asnblob = [SysadminsLV.Asn1Parser.Asn1Utils]::Encode($asnblob, 48)
        $base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($asnblob,"Base64").Trim()
        [void]$out.AppendFormat("{0}{1}", "-----BEGIN PRIVATE KEY-----", [Environment]::NewLine)
        [void]$out.AppendFormat("{0}{1}", $base64, [Environment]::NewLine)
        [void]$out.AppendFormat("{0}{1}", "-----END PRIVATE KEY-----", [Environment]::NewLine)
    } else {
        # PKCS#1 requires RSA identifier in the header.
        # PKCS#1 is an inner structure of PKCS#8 message, therefore no additional encodings are required.
        $base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($asnblob,"Base64").Trim()
        [void]$out.AppendFormat("{0}{1}", "-----BEGIN RSA PRIVATE KEY-----", [Environment]::NewLine)
        [void]$out.AppendFormat("{0}{1}", $base64, [Environment]::NewLine)
        [void]$out.AppendFormat("{0}{1}", "-----END RSA PRIVATE KEY-----", [Environment]::NewLine)
    }
    $base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($Certificate.RawData,"Base64Header")
    $out.Append($base64)
    if ($IncludeChain) {
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = "NoCheck"
        if ($certs) {
            $chain.ChainPolicy.ExtraStore.AddRange($certs)
        }
        [void]$chain.Build($Certificate)
        for ($n = 1; $n -lt $chain.ChainElements.Count; $n++) {
            $base64 = [SysadminsLV.Asn1Parser.AsnFormatter]::BinaryToString($chain.ChainElements[$n].Certificate.RawData,"Base64Header")
            $out.Append($base64)
        }
    }
    [IO.File]::WriteAllLines($OutputFile,$out.ToString())
#endregion
}