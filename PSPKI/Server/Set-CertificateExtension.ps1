function Set-CertificateExtension {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Utils.IServiceOperationResult')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
            if ($_.GetType().FullName -eq "SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbRow") {$true} else {$false}
        })]$Request,
        [Parameter(Mandatory = $true)]
        [Object[]]$Extension,
        [switch]$Remove
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($Req in $Request) {
            $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
            if ($Extension[0] -is [Security.Cryptography.X509Certificates.X509ExtensionCollection] -and !$Remove) {
                foreach ($ext in $Extension[0]) {
                    $CertReqAdm = New-Object SysadminsLV.PKI.Dcom.Implementations.CertRequestAdminD $Req.ConfigString
                    try {
                        $CertReqAdm.SetCertificateExtension($Req.RequestID, $ext)
                        New-Object SysadminsLV.PKI.Utils.ServiceOperationResult 0,
                            "Extension '$([SysadminsLV.PKI.Cryptography.OidExtensions]::Format($ext.Oid, $true))' was addedd to request ID='$($Req.RequestID)'."
                    } catch {
                        throw $_
                    }
                }
            } elseif ($Extension[0] -is [Security.Cryptography.X509Certificates.X509Extension] -and !$Remove) {
                foreach ($ext in $Extension) {
                    $ext = [Security.Cryptography.X509Certificates.X509Extension]$ext
                    $CertReqAdm = New-Object SysadminsLV.PKI.Dcom.Implementations.CertRequestAdminD $Req.ConfigString
                    try {
                        $CertReqAdm.SetCertificateExtension($Req.RequestID, $ext)
                        New-Object SysadminsLV.PKI.Utils.ServiceOperationResult 0,
                            "Extension '$([SysadminsLV.PKI.Cryptography.OidExtensions]::Format($ext.Oid, $true))' was addedd to request ID='$($Req.RequestID)'."
                    } catch {
                        throw $_
                    }
                }
            } elseif ($Remove) {
                foreach ($ext in $Extension) {
                    try {
                        $oid = New-Object Security.Cryptography.Oid $ext
                        [void](New-Object SysadminsLV.Asn1Parser.Universal.Asn1ObjectIdentifier $ext)
                        $CertAdmin.SetCertificateExtension($Req.ConfigString,$Req.RequestID,$oid.Value,0x1,0x2,0)
                        New-Object SysadminsLV.PKI.Utils.ServiceOperationResult 0,
                            "Extension '$([SysadminsLV.PKI.Cryptography.OidExtensions]::Format($oid, $true))' was removed from request ID='$($Req.RequestID)'."
                        Write-Verbose "Extension OID='$($oid.Value)' was removed from request ID='$($Req.RequestID)'."
                    } catch {
                        throw $_
                    }
                }
            } else {
                throw New-Object ArgumentException "The parameter is invalid."
            }
            Clear-ComObject $CertAdmin
        }
    }
}