function Get-EnterprisePKIHealthStatus {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.EnterprisePKI.X509HealthPath')]
[CmdletBinding(DefaultParameterSetName = '__CA')]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = '__CA'
        )]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority[]]$CertificateAuthority,
        [Parameter(Mandatory = $true, ParameterSetName = '__EndCerts')]
        [Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificate,
        # configuration
        [int]$DownloadTimeout = 15,
        [ValidateRange(1,99)]
        [int]$CaCertExpirationThreshold = 80,
        [ValidateRange(1,99)]
        [int]$BaseCrlExpirationThreshold = 80,
        [ValidateRange(1,99)]
        [int]$DeltaCrlExpirationThreshold = 80,
        [ValidateRange(1,99)]
        [int]$OcspCertExpirationThreshold = 80
    )
    begin {
#region native function declarations
$cryptnetsignature = @"
[DllImport("cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern bool CryptRetrieveObjectByUrl(
    //[MarshalAs(UnmanagedType.LPStr)]
    string pszUrl,
    //[MarshalAs(UnmanagedType.LPStr)]
    int pszObjectOid,
    int dwRetrievalFlags,
    int dwTimeout,
    ref IntPtr ppvObject,
    IntPtr hAsyncRetrieve,
    IntPtr pCredentials,
    IntPtr pvVerify,
    IntPtr pAuxInfo
);
"@
Add-Type -MemberDefinition $cryptnetsignature -Namespace "PKI.EnterprisePKI" -Name Cryptnet
$crypt32signature = @"
[DllImport("Crypt32.dll", SetLastError = true)]
public static extern Boolean CertFreeCertificateContext(
    [In] IntPtr pCertContext
);
[DllImport("Crypt32.dll", SetLastError = true)]
public static extern Boolean CertFreeCRLContext(
    [In] IntPtr pCrlContext
);
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct CRL_CONTEXT {
    public int dwCertEncodingType;
    public IntPtr pbCrlEncoded;
    public int cbCrlEncoded;
    public IntPtr pCrlInfo;
    public IntPtr hCertStore;
}
"@
Add-Type -MemberDefinition $crypt32signature -Namespace "PKI.EnterprisePKI" -Name Crypt32
Add-Type @"
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
namespace PKI.EnterprisePKI {
    public enum ChildStatus {
        Ok = 0x0,
        Warning = 0x100,
        Error = 0x8000,
    }
    // 0-49 -- common
    // 50-99 -- certs
    // 100-149 -- crls
    // 150-199 -- ocsp
    public enum UrlStatus {
        // common
        Ok = 0,
        // CRT/CRL/OCSP
        FailedToDownload = 10, NotYetValid = 11, Expired = 12, Expiring = 13,
        InvalidSignature = 14, NetworkRetrievalError = 15,
        // certs only
        Revoked = 50, InvalidCert = 51,
        // CRLs only. ScheduleExpired means that there is a "Next CRL Publish"
        // extension and current time is ahead of "Next CRL Publish value"
        InvalidIssuer = 100, ScheduleExpired = 101, InvalidBase = 102, InvalidCrlType = 103,
        NonCriticalDeltaIndicator = 104, StaleDelta = 105,
        // ocsp only
        MalformedRequest = 151, InternalError = 152, TryLater = 153,
        SignatureRequired = 155, Unauthorized = 156,
        ResponseInvalidData = 160, InvalidSignerCert = 161,
        // CAs only
        Offline,
    }
    public enum UrlType {
        Certificate, Crl, Ocsp
    }
    public class UrlElement {
        ushort error;

        Object hiddenObject;
        public String Name { get; set; }
        public UrlStatus Status {
            get {
                return (UrlStatus)(error & 0xff);
            }
        }
        public String ExtendedErrorInfo { get; set; }
        public Uri Url { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public UrlType UrlType { get; set; }

        public Object GetObject() { return hiddenObject; }
        public void SetObject(Object obj) { hiddenObject = obj; }
        public void SetError(ushort statusCode) {
            error = statusCode;
        }
        public ushort GetError() {
            return error;
        }
        public override String ToString() {
            return Name + ": " + Url + ", expire: " + ExpirationDate + ", Status: " + Status;
        }
    }
    public class CAObject {
        bool isOffline;
        public String Name { get; set; }
        // can be 'Ok', 'Warning', or 'Error'
        public ChildStatus Status {
            get {
                if (isOffline) { return ChildStatus.Error; }
                if (URLs == null) {
                    return ChainStatus == X509ChainStatusFlags.NoError ? ChildStatus.Ok : ChildStatus.Error;
                }
                ChildStatus retValue = ChildStatus.Ok;
                foreach (var url in URLs) {
                    if ((url.GetError() & 0xFF00) > (int)retValue) { retValue = (ChildStatus)(url.GetError() & 0xFF00); }
                }
                return retValue;
            }
        }
        public X509ChainStatusFlags ChainStatus { get; set; }
        public String ExtendedErrorInfo { get; set; }
        public UrlElement[] URLs { get; set; }
        public void Offline() {
            isOffline = true;
        }
    }
    public class X509HealthPath {
        public String Name { get; set; }
        public ChildStatus Status {
            get {
                if (Childs == null || Childs.Length == 0) { return ChildStatus.Ok; }
                return Childs.Any(child => child.Status == ChildStatus.Error)
                    ? ChildStatus.Error
                    : (Childs.Any(child => child.Status == ChildStatus.Warning)
                        ? ChildStatus.Warning
                        : ChildStatus.Ok);
            }
        }
        public CAObject[] Childs { get; set; }
    }
}
"@
#endregion
        #region Error severity
        $s_ok = 0x0
        $s_warning = 0x100
        $s_error = 0x8000
        #endregion

        #region script internal config
        if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
        if ($PSBoundParameters.Debug) {$DebugPreference = "continue"}
        $timeout = $DownloadTimeout * 1000
        #endregion

        #region helper functions
        # returns [X509ChainElement[]]
        $chainRoots = @()
        function __getChain([Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
            Write-Verbose "Entering certificate chaining engine."
            $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $status = $chain.Build($cert)
            Write-Debug "Chain status for certificate '$($cert.Subject)': $status"
            if ($chainRoots -notcontains $chain.ChainElements[0].Certificate.Thumbprint) {
                $chainRoots += $chain.ChainElements[0].Certificate.Thumbprint
            }
            $retValue = New-Object Security.Cryptography.X509Certificates.X509ChainElement[] -ArgumentList $chain.ChainElements.Count
            $chain.ChainElements.CopyTo($retValue,0)
            $chain.Reset()
            $retValue
        }
        # returns [X509Certificate2] or [String] that contains error message
        function __downloadCert($url) {
            Write-Debug "Downloading cert URL: $url."
            $ppvObject = [IntPtr]::Zero
            if ([PKI.EnterprisePKI.Cryptnet]::CryptRetrieveObjectByUrl($url,1,4,$timeout,[ref]$ppvObject,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero)
            ) {
                $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $ppvObject
                Write-Debug "Certificate: $($cert.Subject)"
                $cert
                [void][PKI.EnterprisePKI.Crypt32]::CertFreeCertificateContext($ppvObject)
            } else {
                $hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Debug "URL error: $hresult"
                $CertRequest = New-Object -ComObject CertificateAuthority.Request
                $CertRequest.GetErrorMessageText($hresult,0)
                Clear-ComObject $CertRequest
            }
        }
        # returns [X509CRL2] or [String] that contains error message
        function __downloadCrl($url) {
            Write-Debug "Downloading CRL URL: $url."
            $ppvObject = [IntPtr]::Zero
            if ([PKI.EnterprisePKI.Cryptnet]::CryptRetrieveObjectByUrl($url,2,4,$timeout,[ref]$ppvObject,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero)
            ) {
                $crlContext = [Runtime.InteropServices.Marshal]::PtrToStructure($ppvObject,[Type][PKI.EnterprisePKI.Crypt32+CRL_CONTEXT])
                $rawData = New-Object byte[] -ArgumentList $crlContext.cbCrlEncoded
                [Runtime.InteropServices.Marshal]::Copy($crlContext.pbCrlEncoded,$rawData,0,$rawData.Length)
                $crl = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2 (,$rawData)
                Write-Debug "CRL: $($crl.Issuer)"
                $crl
                [void][PKI.EnterprisePKI.Crypt32]::CertFreeCRLContext($ppvObject)
            } else {
                $hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Debug "URL error: $hresult"
                $CertRequest = New-Object -ComObject CertificateAuthority.Request
                $CertRequest.GetErrorMessageText($hresult,0)
                Clear-ComObject $CertRequest
            }
        }
        # returns PSObject -- UrlPack
        function __getUrl ([Byte[]]$rawData, [bool]$isCert) {
            Write-Verbose "Getting URLs."
            Write-Debug "Getting URLs."
            $URLs = New-Object psobject -Property @{
                CDP = $null;
                AIA = $null;
                OCSP = $null;
                FreshestCRL = $null;
            }
            $ofs = "`n"
            if ($isCert) {
                $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,$rawData)
                # CRL Distribution Points
                Write-Debug "Fetching 'CRL Distribution Points' extension..."
                $e = $cert.Extensions["2.5.29.31"]
                if ($e) {
                    $asn = New-Object Security.Cryptography.AsnEncodedData (,$e.RawData)
                    $cdp = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509CRLDistributionPointsExtension $asn, $false
                    $URLs.CDP = $cdp.GetURLs()
                    Write-Debug "Found $(($URLs.CDP).Length) CDP URLs."
                    if ($URLs.CDP) {$URLs.CDP | ForEach-Object {Write-Debug "$_"}}
                } else {
                    Write-Debug "Missing 'CRL Distribution Points' extension."
                }
                # Authority Information Access
                Write-Debug "Fetching 'Authority Information Access' extension..."
                $e = $cert.Extensions["1.3.6.1.5.5.7.1.1"]
                if ($e) {
                    $asn = New-Object Security.Cryptography.AsnEncodedData (,$e.RawData)
                    $aia = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509AuthorityInformationAccessExtension $asn, $false
                    $URLs.AIA = $aia.CertificationAuthorityIssuer
                    Write-Debug "Found $(($URLs.AIA).Length) Certification Authority Issuer URLs."
                    if ($URLs.AIA) {$URLs.AIA | ForEach-Object {Write-Debug $_}}
                    $URLs.OCSP = $aia.OnlineCertificateStatusProtocol
                    Write-Debug "Found $(($URLs.OCSP).Length) On-line Certificate Status Protocol URLs."
                    if ($URLs.OCSP) {$URLs.OCSP | ForEach-Object {Write-Debug $_}}
                } else {
                    Write-Debug "Missing 'Authority Information Access' extension."
                }
                $URLs
            } else {
                Write-Debug "Fetching 'Freshest CRL' extension..."
                $crl = New-Object SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2 @(,$rawData)
                $e = $crl.Extensions["2.5.29.46"] # Freshest CRL
                if ($e) {
                    $URLs.FreshestCRL = $e.GetURLs()
                    Write-Debug "Found $(($URLs.FreshestCRL).Length) Freshest CRL URLs."
                    if ($URLs.FreshestCRL) {$URLs.FreshestCRL | ForEach-Object {Write-Debug $_}}
                } else {
                    Write-Debug "Missing 'Freshest CRL' extension."
                }
                $URLs
            }
        }
        # returns UrlElement
        function __verifyAIA {
            param (
                [PKI.EnterprisePKI.UrlElement]$urlElement,
                [Security.Cryptography.X509Certificates.X509ChainElement]$CAcert
            )
            Write-Verbose "Entering certificate validation routine."
            Write-Debug "Entering certificate validation routine."
            $cert = $urlElement.GetObject()
            Write-Debug "Leaf certificate: $($cert.Subject)."
            $parent = if ($cert.Subject -eq $cert.Issuer) {
                Write-Debug "Self-signed certificate, issuer is itself."
                $cert
            } else {
                Write-Debug "Issuer candidate: $($CAcert.Certificate.Subject)."
                $CAcert.Certificate
            }
            Write-Debug "Certificate start validity : $($cert.NotBefore)"
            Write-Debug "Certificate end validity   : $($cert.NotAfter)"
            $urlElement.ExpirationDate = $cert.NotAfter
            $subjComp = Compare-Object $cert.SubjectName.RawData $parent.SubjectName.RawData
            $pubKeyComp = Compare-Object $cert.PublicKey.EncodedKeyValue.RawData $parent.PublicKey.EncodedKeyValue.RawData
            $pubKeyParamComp = Compare-Object $cert.PublicKey.EncodedParameters.RawData $parent.PublicKey.EncodedParameters.RawData
            Write-Debug "Subject name binary comparison         : $(if ($subjComp) {'failed'} else {'passed'})"
            Write-Debug "Public key binary comparison           : $(if ($pubKeyComp) {'failed'} else {'passed'})"
            Write-Debug "Public key parameters binary comparison: $(if ($pubKeyParamComp) {'failed'} else {'passed'})"
            $fullTime = ($cert.NotAfter - $cert.NotBefore).TotalSeconds
            $elapsed = ((Get-Date) - $cert.NotBefore).TotalSeconds
            $errorCode = if ($subjComp -or $pubKeyComp -or $pubKeyParamComp) {
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCert
            } elseif ($cert.NotBefore -gt (Get-Date)) {
                Write-Debug "Certificate is not yet valid."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::NotYetValid
            } elseif ($cert.NotAfter -lt (Get-Date)) {
                Write-Debug "Certificate is expired."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::Expired
            } elseif ($CaCertExpirationThreshold -lt $elapsed / $fullTime * 100) {
                Write-Debug "Certificate is about to expire. Elapsed $([int]($elapsed / $fullTime * 100))%"
                $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
            } else {
                Write-Debug "Certificate passed all validity checks."
                $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
            }
            $urlElement.SetError($errorCode)
            $urlElement
        }
        # returns DateTime or Null (for CRL v1)
        function __getCrlNextPublish($crl) {
            $e = $crl.Extensions["1.3.6.1.4.1.311.21.4"]
            if (!$e) {return}
            $dt = try {
                    (New-Object SysadminsLV.Asn1Parser.Universal.Asn1UtcTime -ArgumentList @(,($e.RawData))).Value
                } catch {
                    (New-Object SysadminsLV.Asn1Parser.Universal.Asn1GeneralizedTime -ArgumentList @(,($e.RawData))).Value
                }
        }
        # returns UrlElement. $cert -- issuer candidate/X509ChainElement.
        function __verifyCDP {
            param(
                [PKI.EnterprisePKI.UrlElement]$urlElement,
                [Security.Cryptography.X509Certificates.X509ChainElement]$cert,
                [SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2]$BaseCRL,
                [switch]$DeltaCRL
            )
            Write-Verbose "Entering CRL validation routine..."
            Write-Debug "Entering CRL validation routine..."
            $crl = $urlElement.GetObject()
            Write-Debug "$($crl.Type) start validity : $($crl.ThisUpdate)"
            Write-Debug "$($crl.Type) end validity   : $($crl.NextUpdate)"
            $urlElement.ExpirationDate = $crl.NextUpdate
            [Numerics.BigInteger]$dcrlNumber = $crl.GetCRLNumber()
            Write-Debug "CRL number: $dcrlNumber"
            if ($DeltaCRL) {
                [Numerics.BigInteger]$bcrlNumber = $BaseCRL.GetCRLNumber()
                Write-Debug "Referenced Base CRL number: $bcrlNumber"
                $DeltaCrlIndicator = $crl.Extensions["2.5.29.27"]
                if ($DeltaCrlIndicator -ne $null) {
                    [Numerics.BigInteger]$indicator = (New-Object SysadminsLV.Asn1Parser.Universal.Asn1Integer -ArgumentList @(,($DeltaCrlIndicator.RawData))).Value
                    Write-Debug "Required minimum Base CRL number: $indicator"
                    [bool]$indicatorIsCritical = $DeltaCrlIndicator.Critical
                } else {
                    Write-Debug "Missing 'Delta CRL Indicator' CRL extension."
                }
            }
            $errorCode = if ($DeltaCRL -and ($crl.Type -ne "DeltaCrl")) {
                Write-Debug "Invalid CRL type. Expected Delta CRL, but received Base CRL."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCrlType
            } elseif (!$DeltaCRL -and ($crl.Type -ne "BaseCrl")) {
                Write-Debug "Invalid CRL type. Expected Base CRL, but received Delta CRL."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidCrlType
            } elseif (!$crl.VerifySignature($cert.Certificate, $true)) {
                Write-Debug "CRL signature check failed."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidIssuer
            } elseif ($crl.ThisUpdate -gt [datetime]::Now) {
                Write-Debug "CRL is not yet valid."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::NotYetValid
            } elseif ($crl.NextUpdate -lt [datetime]::Now) {
                Write-Debug "CRL is expired."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::Expired
            } elseif ($DeltaCRL -and !$indicatorIsCritical) {
                Write-Debug "'Delta CRL Indicator' is not critical."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::NonCriticalDeltaIndicator
            } elseif ($DeltaCRL -and ($bcrlNumber -lt $indicator)) {
                Write-Debug "Base CRL number has lower version than version required by 'Delta CRL Indicator' extension."
                $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidBase
            } elseif ($DeltaCRL -and ($dcrlNumber -lt $bcrlNumber)) {
                Write-Debug "Delta CRL is outdated. A new version of Base CRL is available that overlaps current Delta CRL."
                $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::StaleDelta
            } else {
                $dt = __getCrlNextPublish $crl
                if ($dt) {
                    if ((Get-Date) -gt $dt) {
                        Write-Debug "Scheduled CRL publish expired."
                        $urlElement.SetError($s_warning -bor [PKI.EnterprisePKI.UrlStatus]::ScheduleExpired)
                    }
                    $urlElement
                    return
                }
                $fullTime = ($crl.NextUpdate - $crl.ThisUpdate).TotalSeconds
                $elapsed = ((Get-Date) - $crl.ThisUpdate).TotalSeconds
                if ($DeltaCRL) {
                    if ($DeltaCrlExpirationThreshold -lt $elapsed / $fullTime * 100) {
                        Write-Debug "$($crl.Type) is about to expire. Elapsed: $([int]($elapsed / $fullTime * 100))%"
                        $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
                    } else {
                        
                        $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
                    }
                } else {
                    if ($BaseCrlExpirationThreshold -lt $elapsed / $fullTime * 100) {
                        Write-Debug "$($crl.Type) is about to expire. Elapsed: $([int]($elapsed / $fullTime * 100))%"
                        $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
                    } else {
                        $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
                    }
                }
            }
            $urlElement.SetError($errorCode)
            $urlElement
        }
        # returns UrlElement
        function __verifyOCSP {
            param(
                [Security.Cryptography.X509Certificates.X509ChainElement]$cert,
                [PKI.EnterprisePKI.UrlElement]$urlElement
            )
            Write-Verbose "Entering OCSP validation routine..."
            Write-Debug "Entering OCSP validation routine..."
            Write-Debug "URL: $($urlElement.Url.AbsoluteUri)"
            $req = New-Object SysadminsLV.PKI.OcspClient.OCSPRequest $cert.Certificate
            $req.URL = $urlElement.Url
            try {
                $resp = $req.SendRequest()
                $urlElement.SetObject($resp)
                $errorCode = if ($resp.ResponseStatus -ne [SysadminsLV.PKI.OcspClient.OCSPResponseStatus]::Successful) {
                    Write-Debug "OCSP server failed: $($resp.ResponseStatus)"
                    $s_error -bor (150 + $resp.ResponseStatus)
                } elseif (!$resp.SignatureIsValid) {
                    Write-Debug "OCSP response signature validation failed."
                    $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidSignature
                } elseif ([int]$resp.ResponseErrorInformation) {
                    Write-Debug "Response contains invalid data: $($resp.ResponseErrorInformation)"
                    $s_error -bor [PKI.EnterprisePKI.UrlStatus]::ResponseInvalidData
                } elseif (!$resp.SignerCertificateIsValid) {
                    Write-Debug "Signer certificate has one or more issues."
                    $s_error -bor [PKI.EnterprisePKI.UrlStatus]::InvalidSignerCert
                } else {
                    $totalValidity = ($resp.SignerCertificates[0].NotAfter - $resp.SignerCertificates[0].NotBefore).TotalSeconds
                    $elapsed = ((Get-Date) - $resp.SignerCertificates[0].NotBefore).TotalSeconds
                    if ($OcspCertExpirationThreshold -le $elapsed / $totalValidity * 100) {
                        Write-Debug "OCSP signing certificate is about to expire. Elapsed: $($elapsed / $totalValidity * 100)%"
                        $s_warning -bor [PKI.EnterprisePKI.UrlStatus]::Expiring
                    } else {
                        Write-Debug "OCSP response passed all checks."
                        $urlElement.ExpirationDate = $resp.Responses[0].NextUpdate
                        Write-Debug "OCSP response expires: $($urlElement.ExpirationDate)"
                        $s_ok -bor [PKI.EnterprisePKI.UrlStatus]::Ok
                    }
                }
                $urlElement.SetError($errorCode)
            } catch {
                $urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::NetworkRetrievalError)
                $urlElement.ExtendedErrorInfo = $_.Error.Exception.Message
            }
            $urlElement
        }
        # returns CAObject
        function __processCerts ($CAObject, $projectedChain) {
            Write-Verbose "Processing Certification Authority Issuer URLs..."
            Write-Debug "Processing Certification Authority Issuer URLs..."
            for ($n = 0; $n -lt $urlPack.AIA.Length; $n++) {
                $urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                    Name = "AIA Location #$($n + 1)";
                    Url = $urlPack.AIA[$n];
                    UrlType = [PKI.EnterprisePKI.UrlType]::Certificate;
                }
                $obj = __downloadCert $urlElement.Url
                if ($obj -is [Security.Cryptography.X509Certificates.X509Certificate2]) {
                    $urlElement.SetObject($obj)
                    $urlElement = __verifyAIA $urlElement $projectedChain[$n + 1]
                } else {
                    Write-Debug "Failed to download certificate."
                    $urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
                    $urlElement.ExtendedErrorInfo = $obj
                }
                $CAObject.URLs += $urlElement
            }
            $CAObject
        }
        # returns CAObject
        function __processOcsp ($CAObject, $projectedChain) {
            Write-Verbose "Processing On-line Certificate Status Protocol URLs..."
            Write-Debug "Processing On-line Certificate Status Protocol URLs..."
            for ($n = 0; $n -lt $urlPack.OCSP.Length; $n++) {
                $urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                    Name = "OCSP Location #$($n + 1)";
                    Url = $urlPack.OCSP[$n];
                    UrlType = [PKI.EnterprisePKI.UrlType]::Ocsp;
                }
                $urlElement = __verifyOCSP $projectedChain[$n] $urlElement
                $CAObject.URLs += $urlElement
            }
            $CAObject
        }
        # returns X509HealthPath
        function __validateSinglePath {
            param(
                [Security.Cryptography.X509Certificates.X509Certificate2]$cert,
                # this parameter is not used
                [int]$keyIndex = -1
            )
            Write-Verbose "Entering certification path validation routine..."
            Write-Debug "Entering certification path validation routine..."
            if ([IntPtr]::Zero.Equals($cert.Handle)) {
                throw New-Object SysadminsLV.PKI.Exceptions.UninitializedObjectException "The certificate is not initialized."
                return
            }
            $projectedChain = __getChain $cert
            [void]($cert.Issuer -match "CN=([^,]+)")
            Write-Debug "CA name: $($matches[1])"
            $out = if ($keyIndex -lt 0) {
                New-Object PKI.EnterprisePKI.X509HealthPath -Property @{Name = $matches[1]}
            } else {
                New-Object PKI.EnterprisePKI.X509HealthPath -Property @{Name = "$($matches[1]) ($keyIndex)"}
            }
            for ($i = 0; $i -lt $projectedChain.Length; $i++) {
                Write-Debug "========================= $($projectedChain[$i].Certificate.Issuer) ========================="
                # skip self-signed certificate from checking
                if (!(
                    Compare-Object -ReferenceObject $projectedChain[$i].Certificate.SubjectName.RawData `
                        -DifferenceObject $projectedChain[$i].Certificate.IssuerName.RawData)) {
                    Write-Debug "Leaf certificate is self-signed, skip validation."
                    break
                }
                [void]($projectedChain[$i].Certificate.Issuer -match "CN=([^,]+)")
                $CAObject = if ($keyIndex -lt 0) {
                    New-Object PKI.EnterprisePKI.CAObject -Property @{Name = $matches[1]}
                } else {
                    New-Object PKI.EnterprisePKI.CAObject -Property @{Name = "$($matches[1]) ($keyIndex)"}
                }
                $projectedChain | ForEach-Object {[int]$CAObject.ChainStatus += [int]$_.Status}
                $urlpack = __getUrl $projectedChain[$i].Certificate.RawData $true
                # process and validate certificate issuer in the AIA extension
                $CAObject = __processCerts $CAObject $projectedChain
                # process and validate CDP extensions
                for ($n = 0; $n -lt $urlPack.CDP.Length; $n++) {
                    $deltas = @()
                    $urlElement = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                        Name = "CDP Location #$($n + 1)";
                        Url = $urlPack.CDP[$n];
                        UrlType = [PKI.EnterprisePKI.UrlType]::Crl;
                    }
                    $obj = __downloadCrl $urlElement.Url
                    if ($obj -is [SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2]) {
                        $urlElement.SetObject($obj)
                        $urlElement = __verifyCDP $urlElement $projectedChain[$i + 1]
                        $urlPack2 = __getUrl ($urlElement.GetObject()).RawData $false
                        # process and validate FreshestCRL extension if exist
                        for ($m = 0; $m -lt $urlPack2.FreshestCRL.Length; $m++) {
                            # skip duplicate
                            if ($deltas | Where-Object {$_.Url -eq $urlPack2.FreshestCRL[$m]}) {
                                return
                            }
                            $urlElement2 = New-Object PKI.EnterprisePKI.UrlElement -Property @{
                                Name = "DeltaCRL Location #$($m + 1)";
                                Url = $urlPack2.FreshestCRL[$m];
                                UrlType = [PKI.EnterprisePKI.UrlType]::Crl;
                            }
                            $obj2 = __downloadCrl $urlElement2.Url
                            if ($obj2 -is [SysadminsLV.PKI.Cryptography.X509Certificates.X509CRL2]) {
                                $urlElement2.SetObject($obj2)
                                $urlElement2 = __verifyCDP $urlElement2 $projectedChain[$i + 1] $obj -DeltaCRL
                            } else {
                                Write-Debug "Failed to download CRL."
                                $urlElement2.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
                                $urlElement2.ExtendedErrorInfo = $obj2
                            }
                            $deltas += $urlElement2
                        }
                    } else {
                        Write-Debug "Failed to download CRL."
                        $urlElement.SetError($s_error -bor [PKI.EnterprisePKI.UrlStatus]::FailedToDownload)
                        $urlElement.ExtendedErrorInfo = $obj
                    }
                    $CAObject.URLs += $urlElement
                    $CAObject.URLs += $deltas
                }
                # process OCSP links in the AIA extension
                $CAObject = __processOcsp $CAObject $projectedChain
                $out.Childs += $CAObject
            }
            $out
        }
        #endregion
        Write-Debug "Initializing parameterset: $($PsCmdlet.ParameterSetName)."
    }
    process {
        switch ($PsCmdlet.ParameterSetName) {
            '__CA' {
                foreach ($CA in $CertificateAuthority) {
                    if (!$CA.Ping()) {
                        Write-Debug "$($CA.DisplayName): ICertAdmin is down."
                        $retValue = New-Object PKI.EnterprisePKI.CAObject -Property @{Name = $CA.DisplayName}
                        $retValue.Offline()
                        $retValue
                        return
                    }
                    if (!$CA.Type.StartsWith("Enterprise")) {
                        Write-Debug "$($CA.DisplayName): not supported edition. Current: $($CA.Type)."
                        throw "Only Enterprise CAs are supported by this parameterset."
                    }
                    Write-Verbose ("{0} {1} {0}" -f ('=' * 20), $CA.DisplayName)
                    Write-Debug ("{0} {1} {0}" -f ('=' * 20), $CA.DisplayName)
                    Write-Debug "$($CA.DisplayName): retrieving CA Exchange certificate."
                    $xchg = $CA.GetCAExchangeCertificate()
                    __validateSinglePath $xchg
                }
            }
            '__EndCerts' {
                $Certificate | ForEach-Object {__validateSinglePath $_}
            }
        }
    }
}