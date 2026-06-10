function Set-CertificateTemplateAcl {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Security.AccessControl.CertTemplateSecurityDescriptor')]
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
        [Alias('AclObject','Acl')]
        [SysadminsLV.PKI.Security.AccessControl.CertTemplateSecurityDescriptor[]]$InputObject
    )

    begin {
        Assert-CommandRequirement $PREREQ_ADDS -ErrorAction Stop
    }

    process {
        foreach($ACL in $InputObject) {
            $ACL.SetObjectSecurity()
            $ACL
        }
    }
}