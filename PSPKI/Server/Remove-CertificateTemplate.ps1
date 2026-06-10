function Remove-CertificateTemplate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [PKI.CertificateTemplates.CertificateTemplate]$Template
    )
    process {
        Assert-CommandRequirement $PREREQ_ADDS -ErrorAction Stop

        try {$ldap = [ADSI]("LDAP://" + $Template.DN)}
        catch {Write-Error "Specified template '$($Template.DisplayName)' is either invalid or doesn't exist"; return}
        try {([ADSI]$ldap.Parent).Delete("pKICertificateTemplate","CN=$($Template.Name)")}
        catch {Write-Error "Unable to remove certificate template '$($Template.DisplayName)'"}
    }
}