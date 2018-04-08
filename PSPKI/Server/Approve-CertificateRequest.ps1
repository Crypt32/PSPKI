function Approve-CertificateRequest {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Utils.ServiceOperationResult')]
[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateScript({
			if ($_.GetType().FullName -eq "PKI.CertificateServices.DB.RequestRow") {$true} else {$false}
		})]$Request
	)
	process {
		if ((Ping-ICertAdmin $Request.ConfigString)) {
			$CertAdmin = New-Object -ComObject CertificateAuthority.Admin
			try {
				$DM = $CertAdmin.ResubmitRequest($Request.ConfigString,$Request.RequestID)
				switch ($DM) {
					0 {
						New-Object SysadminsLV.PKI.Utils.ServiceOperationResult $DM + 1,
						"The request '$($Request.RequestID)' was not completed.",
						$Request.RequestID
					}
					1 {
						New-Object SysadminsLV.PKI.Utils.ServiceOperationResult $DM + 1,
						"The request '$($Request.RequestID)' failed.",
						$Request.RequestID
					}
					2 {
						New-Object SysadminsLV.PKI.Utils.ServiceOperationResult $DM + 1,
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
						New-Object SysadminsLV.PKI.Utils.ServiceOperationResult $DM + 1,
						"The certificate '$($Request.RequestID)' was issued separately.",
						$Request.RequestID
					}
					5 {
						New-Object SysadminsLV.PKI.Utils.ServiceOperationResult $DM + 1,
						"The request '$($Request.RequestID)' was taken under submission.",
						$Request.RequestID
					}
					default {
						$hresult = "0x" + $("{0:X2}" -f $DM)
						New-Object SysadminsLV.PKI.Utils.ServiceOperationResult $DM + 1,
						"The request with ID='$($Request.RequestID)' was failed due to the error: $hresult.",
						$Request.RequestID
					}
				}
			} finally {[void][Runtime.InteropServices.Marshal]::ReleaseComObject($CertAdmin)}
		} else {Write-ErrorMessage -Source ICertAdminUnavailable -ComputerName $Request.ComputerName}
	}
}