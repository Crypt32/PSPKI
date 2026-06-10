function Get-CertificationAuthority {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.CertificateAuthority')]
[CmdletBinding(DefaultParameterSetName = '__computer')]
    param(
        [Parameter(ParameterSetName = "__computer", Position = 0)]
        [string]$ComputerName = "*",
        [Parameter(ParameterSetName = "__name", Position = 0)]
        [string]$Name = "*",
        [switch]$Enterprise,
        [switch]$Standalone
    )

    Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop


    $DSList = @{}
    if (!$NoDomain) {
        $DSList = [SysadminsLV.PKI.Management.ActiveDirectory.DsPkiContainer]::GetAdPkiContainer("Enroll").EnrollmentServers
    } elseif ($Enterprise -and !$Standalone) {
        # at this point we are in workgroup and only enterprise CAs were requested. There is nothing to return.
        return
    } else {
        # at this point we are in workgroup and enterprise-only CAs are not requested. Attempt to connect to local CA
        # if possible
        [PKI.CertificateServices.CertificateAuthority]::Connect($env:COMPUTERNAME)
        return
    }

    $CertConfig = New-Object SysadminsLV.PKI.Dcom.Implementations.CertConfigD
    $CertSrvList = $CertConfig.EnumConfigEntries()

    # filter by name
    $FinalList = switch ($PsCmdlet.ParameterSetName) {
        '__computer' {$CertSrvList | Where-Object {$_.ComputerName -like $ComputerName}}
        '__name' {$CertSrvList | Where-Object {$_.CommonName -like $Name}}
    }

    # filter by Enterprise/Standalone
    if ($PSBoundParameters.ContainsKey("Enterprise") -or $PSBoundParameters.ContainsKey("Standalone")) {
        if ($PSBoundParameters.ContainsKey("Enterprise") -and !$PSBoundParameters.ContainsKey("Standalone")) {
            $tempList = $DSList | Where-Object {($_.Flags -band [SysadminsLV.PKI.Management.ActiveDirectory.DsEnrollServerFlag]::NoTemplateSupport) -eq 0}
        } elseif (!$PSBoundParameters.ContainsKey("Enterprise") -and $PSBoundParameters.ContainsKey("Standalone")) {
            $tempList = $DSList | Where-Object {($_.Flags -band [SysadminsLV.PKI.Management.ActiveDirectory.DsEnrollServerFlag]::NoTemplateSupport) -gt 0}
        } else {
            $tempList = $DSList
        }
        $tempList = $tempList | ForEach-Object {$_.ComputerName}
        $FinalList = $FinalList | Where-Object {$_.ComputerName -in $tempList}
    }
    $FinalList | ForEach-Object {
        [PKI.CertificateServices.CertificateAuthority]::Connect($_.ComputerName)
    }
}