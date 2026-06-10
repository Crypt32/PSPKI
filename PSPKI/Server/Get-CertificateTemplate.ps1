function Get-CertificateTemplate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateTemplates.CertificateTemplate')]
[CmdletBinding(DefaultParameterSetName='Name')]
    param(
        [Parameter(ParameterSetName = "Name")]
        [String[]]$Name = "*",
        [Parameter(ParameterSetName = "DisplayName")]
        [String[]]$DisplayName = "*",
        [Parameter(ParameterSetName = "OID")]
        [String[]]$OID = "*"
    )
    Assert-CommandRequirement $PREREQ_ADDS -ErrorAction Stop

    $temps = @()
    $vtemps = @()
    $ldap = [ADSI]"LDAP://CN=Certificate Templates,$PkiConfigContext"
    $ldap.psbase.children | ForEach-Object {
        $temps += New-Object psobject -Property @{
            Name = $_.Properties["cn"].Value;
            DisplayName = $_.Properties["DisplayName"].Value;
            OID = $_.Properties["msPKI-Cert-Template-OID"].Value;
        }
    }
    switch ($PsCmdlet.ParameterSetName) {
        "DisplayName" {
            foreach ($item in $DisplayName) {
                if ($item.Contains("*") -or $item.Contains("?")) {$vtemps += ($temps | Where-Object {$_.DisplayName -like $item})}
                else {
                    if (($temps | Where-Object {$_.DisplayName -eq $item})) {
                        $vtemps += $temps | Where-Object {$_.DisplayName -eq $item}
                    } else {
                        Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundException `
                        -Message "Cannot find certificate template with the following display name '$item'. Verify the template display name and call the cmdlet again."
                    }
                }
            }
        }
        "Name" {
            foreach ($item in $Name) {
                if ($item.Contains("*") -or $item.Contains("?")) {$vtemps += ($temps | Where-Object {$_.Name -like $item})}
                else {
                    if (($temps | Where-Object {$_.Name -eq $item})) {
                        $vtemps += $temps | Where-Object {$_.Name -eq $item}
                    } else {
                        Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundException `
                        -Message "Cannot find certificate template with the following name '$item'. Verify the template name and call the cmdlet again."
                    }
                }
            }
        }
        "OID" {
            foreach ($item in $OID) {
                if ($item.Contains("*") -or $item.Contains("?")) {$vtemps += ($temps | Where-Object {$_.OID -like $item})}
                else {
                    if (($temps | Where-Object {$_.OID -eq $item})) {
                        $vtemps += $temps | Where-Object {$_.OID -eq $item}
                    } else {
                        Write-Error -Category ObjectNotFound -ErrorId ObjectNotFoundException `
                        -Message "Cannot find certificate template with the following OID '$item'. Verify the template OID and call the cmdlet again."
                    }
                }
            }
        }
    }
    $vtemps | Where-Object {$_} | ForEach-Object {[SysadminsLV.PKI.CertificateTemplates.CertificateTemplateFactory]::CreateFromCommonNameDs($_.Name)}
}