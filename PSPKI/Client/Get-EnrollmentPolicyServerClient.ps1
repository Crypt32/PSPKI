function Get-EnrollmentPolicyServerClient {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.Enrollment.Policy.PolicyServerClient[]')]
[CmdletBinding()]
    param(
        [switch]$UserContext
    )
    [PKI.Enrollment.Autoenrollment]::GetPolicyServers($UserContext)
}