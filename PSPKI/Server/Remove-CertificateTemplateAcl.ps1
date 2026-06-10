function Remove-CertificateTemplateAcl {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('SysadminsLV.PKI.Security.AccessControl.CertTemplateSecurityDescriptor')]
[CmdletBinding(DefaultParameterSetName = '__identity')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
        [Alias('AclObject','Acl')]
        [SysadminsLV.PKI.Security.AccessControl.CertTemplateSecurityDescriptor[]]$InputObject,
        [Parameter(Mandatory = $true, ParameterSetName = '__identity')]
        [Security.Principal.NTAccount[]]$Identity,
        [Parameter(Mandatory = $true, ParameterSetName = '__identity')]
        [Security.AccessControl.AccessControlType]$AccessType = "Allow",
        [Parameter(Mandatory = $true, ParameterSetName = '__purge')]
        [switch]$Force
    )

    begin {
        Assert-CommandRequirement $PREREQ_ADDS -ErrorAction Stop
    }

    process {
        foreach($ACL in $InputObject) {
            switch ($PSCmdlet.ParameterSetName) {
                '__purge' {
                    if ($Force) {
                        $aceArray = $ACL.Access | ForEach-Object {$_}
                        $aceArray | ForEach-Object {
                            $ACL.PurgeAccessRules($_.IdentityReference)
                        }
                    }
                }
                '__identity' {
                    $Identity | ForEach-Object {
                        [void]$ACL.RemoveAccessRule($_, $AccessType)
                    }
                }
            }
            $ACL
        }
    }
}