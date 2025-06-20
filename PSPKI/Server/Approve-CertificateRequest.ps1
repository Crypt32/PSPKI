function Approve-CertificateRequest {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Utils.IServiceOperationResult')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
            if ($_.GetType().FullName -eq "SysadminsLV.PKI.Management.CertificateServices.Database.AdcsDbRow") {$true} else {$false}
        })]$Request
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
        $ConfigString = ""
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
    }
    process {
        if ((Ping-ICertAdmin $Request.ConfigString)) {
            # if this is first item in pipeline, then $ConfigString is null.
            # cache new config string and instantiate ICertAdmin.
            # do the same if config string doesn't match cached one.
            if (!$ConfigString -or ($ConfigString -ne $Request.ConfigString)) {
                $ConfigString = $Request.ConfigString
                Clear-ComObject $CertAdmin
                $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
            }
            $DispMsg = $CertAdmin.ResubmitRequest($Request.ConfigString,$Request.RequestID)
            switch ($DispMsg) {
                0 {
                    New-Object SysadminsLV.PKI.Utils.ServiceOperationResult ($DispMsg + 1),
                    "The request '$($Request.RequestID)' was not completed.",
                    $Request.RequestID
                }
                1 {
                    New-Object SysadminsLV.PKI.Utils.ServiceOperationResult ($DispMsg + 1),
                    "The request '$($Request.RequestID)' failed.",
                    $Request.RequestID
                }
                2 {
                    New-Object SysadminsLV.PKI.Utils.ServiceOperationResult ($DispMsg + 1),
                    "The request '$($Request.RequestID)' was denied.",
                    $Request.RequestID
                }
                3 {
                    New-Object SysadminsLV.PKI.Utils.ServiceOperationResult 0,
                    "The certificate '$($Request.RequestID)' was issued.",
                    $Request.RequestID
                }
                4 {
                    # not implemented in ADCS
                    New-Object SysadminsLV.PKI.Utils.ServiceOperationResult ($DispMsg + 1),
                    "The certificate '$($Request.RequestID)' was issued separately.",
                    $Request.RequestID
                }
                5 {
                    New-Object SysadminsLV.PKI.Utils.ServiceOperationResult ($DispMsg + 1),
                    "The request '$($Request.RequestID)' was taken under submission.",
                    $Request.RequestID
                }
                default {
                    $hresult = "0x" + $("{0:X2}" -f $DispMsg)
                    New-Object SysadminsLV.PKI.Utils.ServiceOperationResult ($DispMsg + 1),
                    "The request with ID='$($Request.RequestID)' was failed with error: $hresult.",
                    $Request.RequestID
                }
            }
        } else {Write-ErrorMessage -Source ICertAdminUnavailable -ComputerName $Request.ComputerName}
    }
    end {
        Clear-ComObject $CertAdmin
    }
}