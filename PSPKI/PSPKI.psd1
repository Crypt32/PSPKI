@{

    # Script module or binary module file associated with this manifest
    RootModule = 'PSPKI.psm1'

    # Version number of this module.
    ModuleVersion = '4.3.0'

    # ID used to uniquely identify this module
    GUID = '08a70230-ae58-48af-ae73-e4276b6ef1eb'

    # Author of this module
    Author = 'Vadims Podans'

    # Company or vendor of this module
    CompanyName = 'Sysadmins LV'

    # Copyright statement for this module
    Copyright = '(c) 2011 - 2025 Sysadmins LV. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'This module contains public key infrastructure and certificate management functions. Support site: https://www.sysadmins.lv/projects/pspki/default.aspx'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '3.0'

    # Name of the Windows PowerShell host required by this module
    PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    PowerShellHostVersion = '1.0'

    # Minimum version of the .NET Framework required by this module
    DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = ''

    # Processor architecture (None, X86, Amd64, IA64) required by this module
    ProcessorArchitecture = 'Amd64'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @(
        '.\Library\SysadminsLV.Asn1Parser.dll',
        '.\Library\SysadminsLV.PKI.dll',
        '.\Library\SysadminsLV.PKI.OcspClient.dll',
        '.\Library\SysadminsLV.PKI.Win.dll',
        '.\Library\Interop.CERTADMINLib.dll',
        '.\Library\Interop.CERTCLILib.dll',
        '.\Library\Interop.CERTENROLLLib.dll',
        '.\Library\System.Security.Cryptography.Pkcs.dll'
    )

    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @('.\Types\PSPKI.Types.ps1xml')

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @('.\Types\PSPKI.Format.ps1xml')

    # Modules to import as nested modules of the module specified in ModuleToProcess
    NestedModules = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Add-AdCertificate',
        'Add-AdCertificateRevocationList',
        'Add-AuthorityInformationAccess',
        'Add-CAKRACertificate',
        'Add-CATemplate',
        'Add-CertificateTemplateAcl',
        'Add-CertificationAuthorityAcl',
        'Add-CRLDistributionPoint',
        'Add-ExtensionList',
        'Add-OnlineResponderAcl',
        'Add-OnlineResponderArrayMember',
        'Add-OnlineResponderLocalCrlEntry',
        'Add-OnlineResponderRevocationConfiguration',
        'Approve-CertificateRequest',
        'Connect-CertificationAuthority',
        'Connect-OnlineResponder',
        'Convert-PemToPfx',
        'Convert-PfxToPem',
        'Deny-CertificateRequest',
        'Disable-CertificateRevocationListFlag',
        'Disable-InterfaceFlag',
        'Disable-KeyRecoveryAgentFlag',
        'Disable-PolicyModuleFlag',
        'Enable-CertificateRevocationListFlag',
        'Enable-InterfaceFlag',
        'Enable-KeyRecoveryAgentFlag',
        'Enable-PolicyModuleFlag',
        'Get-AdcsDatabaseRow',
        'Get-ADKRACertificate',
        'Get-AdPkiContainer',
        'Get-AuthorityInformationAccess',
        'Get-CACryptographyConfig',
        'Get-CAExchangeCertificate',
        'Get-CAKRACertificate',
        'Get-CATemplate',
        'Get-CertificateContextProperty',
        'Get-CertificateRequest',
        'Get-CertificateRevocationList',
        'Get-CertificateRevocationListFlag',
        'Get-CertificateTemplate',
        'Get-CertificateTemplateAcl',
        'Get-CertificateTrustList',
        'Get-CertificateValidityPeriod',
        'Get-CertificationAuthority',
        'Get-CertificationAuthorityAcl',
        'Get-CertificationAuthorityDbSchema',
        'Get-CryptographicServiceProvider',
        'Get-CRLDistributionPoint',
        'Get-CRLValidityPeriod',
        'Get-EnrollmentPolicyServerClient',
        'Get-EnterprisePKIHealthStatus',
        'Get-ErrorMessage',
        'Get-ExtensionList',
        'Get-FailedRequest',
        'Get-InterfaceFlag',
        'Get-IssuedRequest',
        'Get-KeyRecoveryAgentFlag',
        'Get-ObjectIdentifier',
        'Get-ObjectIdentifierEx',
        'Get-OnlineResponderAcl',
        'Get-OnlineResponderRevocationConfiguration',
        'Get-PendingRequest',
        'Get-PolicyModuleFlag',
        'Get-RequestArchivedKey',
        'Get-RevokedRequest',
        'Import-LostCertificate',
        'Install-CertificateResponse',
        'New-SelfSignedCertificateEx',
        'Ping-ICertInterface',
        'Publish-CRL',
        'Receive-Certificate',
        'Register-ObjectIdentifier',
        'Remove-AdCertificate',
        'Remove-AdCertificateRevocationList',
        'Remove-AdcsDatabaseRow',
        'Remove-AuthorityInformationAccess',
        'Remove-CAKRACertificate',
        'Remove-CATemplate',
        'Remove-CertificatePrivateKey',
        'Remove-CertificateTemplate',
        'Remove-CertificateTemplateAcl',
        'Remove-CertificationAuthorityAcl',
        'Remove-CRLDistributionPoint',
        'Remove-ExtensionList',
        'Remove-OnlineResponderAcl',
        'Remove-OnlineResponderArrayMember',
        'Remove-OnlineResponderLocalCrlEntry',
        'Remove-OnlineResponderRevocationConfiguration',
        'Restart-CertificationAuthority',
        'Restart-OnlineResponder',
        'Restore-CertificateRevocationListFlagDefault',
        'Restore-KeyRecoveryAgentFlagDefault',
        'Restore-PolicyModuleFlagDefault',
        'Revoke-Certificate',
        'Set-AuthorityInformationAccess',
        'Set-CACryptographyConfig',
        'Set-CAKRACertificate',
        'Set-CATemplate',
        'Set-CertificateExtension',
        'Set-CertificateTemplateAcl',
        'Set-CertificateValidityPeriod',
        'Set-CertificationAuthorityAcl',
        'Set-CRLDistributionPoint',
        'Set-CRLValidityPeriod',
        'Set-ExtensionList',
        'Set-OnlineResponderAcl',
        'Set-OnlineResponderProperty',
        'Set-OnlineResponderRevocationConfiguration',
        'Show-Certificate',
        'Show-CertificateRevocationList',
        'Show-CertificateTrustList',
        'Start-CertificationAuthority',
        'Start-OnlineResponder',
        'Stop-CertificationAuthority',
        'Stop-OnlineResponder',
        'Submit-CertificateRequest',
        'Test-WebServerSSL',
        'Unregister-ObjectIdentifier'
    )

    # Cmdlets to export from this module
    CmdletsToExport = '*'

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module
    AliasesToExport = @(
        'Add-AdCrl',
        'Add-AIA',
        'Add-CAAccessControlEntry',
        'Add-CAACL',
        'Add-CDP',
        'Add-OCSPACL',
        'Connect-CA',
        'Disable-CRLFlag',
        'Disable-KRAFlag',
        'Enable-CRLFlag',
        'Enable-KRAFlag',
        'Get-AIA',
        'Get-CA',
        'Get-CAACL',
        'Get-CASecurityDescriptor',
        'Get-CDP',
        'Get-CRL',
        'Get-CRLFlag',
        'Get-Csp',
        'Get-CTL',
        'Get-KRAFlag',
        'Get-OCSPACL',
        'oid',
        'oid2',
        'Remove-AdCrl',
        'Remove-AIA',
        'Remove-CAAccessControlEntry',
        'Remove-CAACL',
        'Remove-CDP',
        'Remove-OCSPACL',
        'Remove-Request',
        'Restore-CRLFlagDefault',
        'Restore-KRAFlagDefault',
        'Set-AIA',
        'Set-CAACL',
        'Set-CASecurityDescriptor',
        'Set-CDP',
        'Set-OCSPACL',
        'Show-CRL',
        'Show-CTL'
    )

    # List of all modules packaged with this module
    ModuleList = @()

    # List of all files packaged with this module
    FileList = @('PSPKI.psd1','PSPKI.psm1','.\Types\PSPKI.Types.ps1xml','.\Types\PSPKI.Format.ps1xml','about_PSPKI_Module.help.txt','.\Library\SysadminsLV.PKI.dll')

    # Private data to pass to the module specified in ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @("PKI","Certificate","CertificateAuthority","ADCS","X509","X.509","Windows")
            ProjectUri = 'https://www.sysadmins.lv/projects/pspki/default.aspx'
            LicenseUri = 'https://github.com/Crypt32/PSPKI/blob/master/License.md'
            ReleaseNotes = 'Release notes are available at: https://github.com/Crypt32/PSPKI/releases'
        }
    }
}