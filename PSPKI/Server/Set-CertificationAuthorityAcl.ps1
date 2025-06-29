function Set-CertificationAuthorityAcl {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Security.AccessControl.CertSrvSecurityDescriptor')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('AclObject','Acl')]
        [SysadminsLV.PKI.Security.AccessControl.CertSrvSecurityDescriptor[]]$InputObject,
        [switch]$RestartCA
    )
    begin {
        Assert-CommandRequirement $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach($ACL in $InputObject) {
            $ACL.SetObjectSecurity($RestartCA)
            $ACL
        }
    }
}