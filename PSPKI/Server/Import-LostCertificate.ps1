function Import-LostCertificate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('System.Int64')]
[CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CA')]
        [PKI.CertificateServices.CertificateAuthority]$CertificationAuthority,
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]$Path,
        [Parameter(Mandatory = $true, ParameterSetName = 'X509Certificate2')]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true, ParameterSetName = 'RawData')]
        [Byte[]]$RawData
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        if ((Ping-ICertAdmin $CertificationAuthority.ConfigString)) {
            $CertAdmin = New-Object -ComObject CertificateAuthority.Admin
            try {
                switch ($PsCmdlet.ParameterSetName) {
                    "Path" {
                        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $Path
                    }
                    "X509Certificate2" {                    
                        $cert = $Certificate
                    }
                    "RawData" {
                        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,$RawData)
                    }
                }
                $Base64 = [Convert]::ToBase64String($cert.RawData)
                [Int64]$RowID = $CertAdmin.ImportCertificate($CertificationAuthority.ConfigString,$Base64,0x1)
                $RowID
            } finally { }
        } else {Write-ErrorMessage -Source ICertAdminUnavailable $CertificationAuthority.ComputerName}
    }
}