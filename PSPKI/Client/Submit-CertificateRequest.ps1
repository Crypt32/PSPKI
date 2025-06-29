function Submit-CertificateRequest {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.Enrollment.CertRequestStatus')]
[CmdletBinding(DefaultParameterSetName = '__dcomPath')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = '__dcomPath')]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = '__xcepPath')]
        [string[]]$Path,
        [Parameter(Mandatory = $true, ParameterSetName = '__dcomRaw')]
        [Parameter(Mandatory = $true, ParameterSetName = '__xcepRaw')]
        [string[]]$RawRequest,
        [Parameter(Mandatory = $true, ParameterSetName = '__dcomPath')]
        [Parameter(Mandatory = $true, ParameterSetName = '__dcomRaw')]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority]$CertificationAuthority,
        [Parameter(Mandatory = $true, ParameterSetName = '__xcepPath')]
        [Parameter(Mandatory = $true, ParameterSetName = '__xcepRaw')]
        [Alias('CEP')]
        [PKI.Enrollment.Policy.PolicyServerClient]$EnrollmentPolicyServer,
        [Parameter(Mandatory = $false, ParameterSetName = '__xcepPath')]
        [Parameter(Mandatory = $false, ParameterSetName = '__xcepRaw')]
        [System.Management.Automation.PSCredential]$Credential,
        [String[]]$Attribute
    )
    begin {
        $ErrorActionPreference = "Stop"
        $CertRequest = New-Object -ComObject CertificateAuthority.Request
        switch ($PsCmdlet.ParameterSetName) {
            "__xcep" {
                if (![string]::IsNullOrEmpty($Credential.UserName)) {
                    switch ($EnrollmentPolicyServer.Authentication) {
                        "UserNameAndPassword" {
                            $CertRequest.SetCredential(
                                0,
                                [int]$EnrollmentPolicyServer.Authentication,
                                $Credential.UserName,
                                [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
                                )
                            )
                        }
                        "ClientCertificate" {
                            $CertRequest.SetCredential(
                                0,
                                [int]$EnrollmentPolicyServer.Authentication,
                                $Credential.UserName,
                                $null
                            )
                        }
                    }
                }
            }
            "__dcom" {
                if (!$CertificationAuthority.PingRequest()) {
                    $e = New-Object SysadminsLV.PKI.Exceptions.ServerUnavailableException $CertificationAuthority.DisplayName
                    throw $e
                }
            }
        }
        if ($Attribute -eq $null) {
            $strAttribute = [string]::Empty
        } else {
            $SB = New-Object Text.StringBuilder
            foreach ($attrib in $Attribute) {
                [Void]$SB.Append($attrib + "`n")
            }
            $strAttribute = $SB.ToString()
            $strAttribute = $strAttribute.Substring(0,$strAttribute.Length - 1)
        }
        
        function Submit-CertificateRequestInternal([string]$RequestContent) {
            try {
                $Status = $CertRequest.Submit(0xff, $RequestContent, $strAttribute, $CertificationAuthority.ConfigString)
                $Output = New-Object PKI.Enrollment.CertRequestStatus -Property @{
                    CertificationAuthority = $CertificationAuthority;
                    Status = $Status;
                    RequestID = $CertRequest.GetRequestId()
                }
                if ($Status -eq 3) {
                    $base64 = $CertRequest.GetCertificate(1)
                    $Output.Certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (,[Convert]::FromBase64String($base64))
                } else {
                    $Output.ErrorInformation = $CertRequest.GetDispositionMessage()
                }
                $Output
            } catch {throw $_}
        }
    }
    process {
        $Requests = @()

        if($Path -ne $null) {
            $Path | ForEach-Object {
                $RequestContent = [IO.File]::ReadAllText((Resolve-Path $_).ProviderPath)
                Submit-CertificateRequestInternal $RequestContent
            }
        } elseif ($RawRequest -ne $null) {
            $RawRequest | ForEach-Object {
                Submit-CertificateRequestInternal $_
            }
        } else {
            Write-Error "Either '-Path' or '-RawRequest' parameter must be specified."
        }
    }
}