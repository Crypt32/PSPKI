# PowerShell PKI Module

### Project Description

This module is intended to simplify various PKI and Active Directory Certificate Services management tasks by using automation with Windows PowerShell.

This module is intended for Certification Authority management. For local certificate store management you should consider to use [Quest AD PKI cmdlets](http://www.quest.com/powershell/activeroles-server.aspx).

#### Relationships between Microsoft PKI and PSPKI modules

Starting with Windows 8/Windows Server 2012, a **PKI** module is installed along with AD CS Remote Server Administration Tools. This module is maintained by Microsoft. **PSPKI** is open-source community module and uses completely different codebase.

### Documentation

All documentation is available at Sysadmins LV: [PowerShell PKI Module](https://www.sysadmins.lv/projects/pspki/default.aspx)

### Download and install PowerShell PKI module from the PowerShell Gallery using PowerShell
```PowerShell
Install-Module -Name PSPKI
```
Latest stable version: ![image](https://img.shields.io/powershellgallery/v/PSPKI)

### Module Requirements

* ![image](https://img.shields.io/badge/PowerShell-3.0-blue.svg)
* ![image](https://img.shields.io/badge/.NET_Framework-4.7.2-blue.svg)

This module can run on any of the specified operating system:
* Windows Server 2008 R2/2012/2012 R2/2016/2019/2022/2025
* Windows 7/8/8.1/10/11

**Module installation requires installed AD CS RSAT (Remote System Administration Tools for Active Directory Certificate Services)**

### Certificate services support

This module supports Enterprise or Standalone Certification Authority (CA) servers that are running one the following operating systems:
* Windows Server 2003/2003 R2
* Windows Server 2008 (including Server Core)
* Windows Server 2008 R2 (including Server Core)
* Windows Server 2012 (including Server Core)
* Windows Server 2012 R2 (including Server Core)
* Windows Server 2016 (including Server Core)
* Windows Server 2019 (including Server Core)
* Windows Server 2022 (including Server Core)
* Windows Server 2025 (including Server Core)

### Online Responder support

This module supports Online Certificate Status Protocol (OCSP) servers that are running one the following operating systems:
* Windows Server 2008 Enterprise (Full Installation)
* Windows Server 2008 R2 Enterprise (Full Installation)
* Windows Server 2012 (including Server Core)
* Windows Server 2012 R2 (including Server Core)
* Windows Server 2016 (including Server Core)
* Windows Server 2019 (including Server Core)
* Windows Server 2022 (including Server Core)
* Windows Server 2025 (including Server Core)

### Full Command List ###
* [Add-AdCertificate](https://www.sysadmins.lv/projects/pspki/Add-AdCertificate.aspx)
* [Add-AdCertificateRevocationList](https://www.sysadmins.lv/projects/pspki/Add-AdCertificateRevocationList.aspx) (Alias: **Add-AdCrl**)
* [Add-AuthorityInformationAccess](https://www.sysadmins.lv/projects/pspki/Add-AuthorityInformationAccess.aspx) (Alias: **Add-AIA**)
* [Add-CAKRACertificate](https://www.sysadmins.lv/projects/pspki/Add-CAKRACertificate.aspx)
* [Add-CATemplate](https://www.sysadmins.lv/projects/pspki/Add-CATemplate.aspx)
* [Add-CertificateTemplateAcl](https://www.sysadmins.lv/projects/pspki/Add-CertificateTemplateAcl.aspx)
* [Add-CertificationAuthorityAcl](https://www.sysadmins.lv/projects/pspki/Add-CertificationAuthorityAcl.aspx) (Alias: **Add-CAAccessControlEntry Add-CAACL**)
* [Add-CRLDistributionPoint](https://www.sysadmins.lv/projects/pspki/Add-CRLDistributionPoint.aspx) (Alias: **Add-CDP**)
* [Add-ExtensionList](https://www.sysadmins.lv/projects/pspki/Add-ExtensionList.aspx)
* [Add-OnlineResponderAcl](https://www.sysadmins.lv/projects/pspki/Add-OnlineResponderAcl.aspx) (Alias: **Add-OCSPACL**)
* [Add-OnlineResponderArrayMember](https://www.sysadmins.lv/projects/pspki/Add-OnlineResponderArrayMember.aspx)
* [Add-OnlineResponderLocalCrlEntry](https://www.sysadmins.lv/projects/pspki/Add-OnlineResponderLocalCrlEntry.aspx)
* [Add-OnlineResponderRevocationConfiguration](https://www.sysadmins.lv/projects/pspki/Add-OnlineResponderRevocationConfiguration.aspx)
* [Approve-CertificateRequest](https://www.sysadmins.lv/projects/pspki/Approve-CertificateRequest.aspx)
* [Connect-CertificationAuthority](https://www.sysadmins.lv/projects/pspki/Connect-CertificationAuthority.aspx) (Alias: **Connect-CA**)
* [Connect-OnlineResponder](https://www.sysadmins.lv/projects/pspki/Connect-OnlineResponder.aspx)
* [Convert-PemToPfx](https://www.sysadmins.lv/projects/pspki/Convert-PemToPfx.aspx)
* [Convert-PfxToPem](https://www.sysadmins.lv/projects/pspki/Convert-PfxToPem.aspx)
* [Deny-CertificateRequest](https://www.sysadmins.lv/projects/pspki/Deny-CertificateRequest.aspx)
* [Disable-CertificateRevocationListFlag](https://www.sysadmins.lv/projects/pspki/Disable-CertificateRevocationListFlag.aspx) (Alias: **Disable-CRLFlag**)
* [Disable-InterfaceFlag](https://www.sysadmins.lv/projects/pspki/Disable-InterfaceFlag.aspx)
* [Disable-KeyRecoveryAgentFlag](https://www.sysadmins.lv/projects/pspki/Disable-KeyRecoveryAgentFlag.aspx) (Alias: **Disable-KRAFlag**)
* [Disable-PolicyModuleFlag](https://www.sysadmins.lv/projects/pspki/Disable-PolicyModuleFlag.aspx)
* [Enable-CertificateRevocationListFlag](https://www.sysadmins.lv/projects/pspki/Enable-CertificateRevocationListFlag.aspx) (Alias: **Enable-CRLFlag**)
* [Enable-InterfaceFlag](https://www.sysadmins.lv/projects/pspki/Enable-InterfaceFlag.aspx)
* [Enable-KeyRecoveryAgentFlag](https://www.sysadmins.lv/projects/pspki/Enable-KeyRecoveryAgentFlag.aspx) (Alias: **Enable-KRAFlag**)
* [Enable-PolicyModuleFlag](https://www.sysadmins.lv/projects/pspki/Enable-PolicyModuleFlag.aspx)
* [Get-AdcsDatabaseRow](https://www.sysadmins.lv/projects/pspki/Get-AdcsDatabaseRow.aspx)
* [Get-ADKRACertificate](https://www.sysadmins.lv/projects/pspki/Get-ADKRACertificate.aspx)
* [Get-AdPkiContainer](https://www.sysadmins.lv/projects/pspki/Get-AdPkiContainer.aspx)
* [Get-AuthorityInformationAccess](https://www.sysadmins.lv/projects/pspki/Get-AuthorityInformationAccess.aspx) (Alias: **Get-AIA**)
* [Get-CACryptographyConfig](https://www.sysadmins.lv/projects/pspki/Get-CACryptographyConfig.aspx)
* [Get-CAExchangeCertificate](https://www.sysadmins.lv/projects/pspki/Get-CAExchangeCertificate.aspx)
* [Get-CAKRACertificate](https://www.sysadmins.lv/projects/pspki/Get-CAKRACertificate.aspx)
* [Get-CATemplate](https://www.sysadmins.lv/projects/pspki/Get-CATemplate.aspx)
* [Get-CertificateContextProperty](https://www.sysadmins.lv/projects/pspki/Get-CertificateContextProperty.aspx)
* [Get-CertificateRequest](https://www.sysadmins.lv/projects/pspki/Get-CertificateRequest.aspx)
* [Get-CertificateRevocationList](https://www.sysadmins.lv/projects/pspki/Get-CertificateRevocationList.aspx) (Alias: **Get-CRL**)
* [Get-CertificateRevocationListFlag](https://www.sysadmins.lv/projects/pspki/Get-CertificateRevocationListFlag.aspx) (Alias: **Get-CRLFlag**)
* [Get-CertificateTemplate](https://www.sysadmins.lv/projects/pspki/Get-CertificateTemplate.aspx)
* [Get-CertificateTemplateAcl](https://www.sysadmins.lv/projects/pspki/Get-CertificateTemplateAcl.aspx)
* [Get-CertificateTrustList](https://www.sysadmins.lv/projects/pspki/Get-CertificateTrustList.aspx) (Alias: **Get-CTL**)
* [Get-CertificateValidityPeriod](https://www.sysadmins.lv/projects/pspki/Get-CertificateValidityPeriod.aspx)
* [Get-CertificationAuthority](https://www.sysadmins.lv/projects/pspki/Get-CertificationAuthority.aspx) (Alias: **Get-CA**)
* [Get-CertificationAuthorityAcl](https://www.sysadmins.lv/projects/pspki/Get-CertificationAuthorityAcl.aspx) (Alias: **Get-CAACL Get-CASecurityDescriptor**)
* [Get-CertificationAuthorityDbSchema](https://www.sysadmins.lv/projects/pspki/Get-CertificationAuthorityDbSchema.aspx)
* [Get-CryptographicServiceProvider](https://www.sysadmins.lv/projects/pspki/Get-CryptographicServiceProvider.aspx) (Alias: **Get-Csp**)
* [Get-CRLDistributionPoint](https://www.sysadmins.lv/projects/pspki/Get-CRLDistributionPoint.aspx) (Alias: **Get-CDP**)
* [Get-CRLValidityPeriod](https://www.sysadmins.lv/projects/pspki/Get-CRLValidityPeriod.aspx)
* [Get-EnrollmentPolicyServerClient](https://www.sysadmins.lv/projects/pspki/Get-EnrollmentPolicyServerClient.aspx)
* [Get-EnterprisePKIHealthStatus](https://www.sysadmins.lv/projects/pspki/Get-EnterprisePKIHealthStatus.aspx)
* [Get-ErrorMessage](https://www.sysadmins.lv/projects/pspki/Get-ErrorMessage.aspx)
* [Get-ExtensionList](https://www.sysadmins.lv/projects/pspki/Get-ExtensionList.aspx)
* [Get-FailedRequest](https://www.sysadmins.lv/projects/pspki/Get-FailedRequest.aspx)
* [Get-InterfaceFlag](https://www.sysadmins.lv/projects/pspki/Get-InterfaceFlag.aspx)
* [Get-IssuedRequest](https://www.sysadmins.lv/projects/pspki/Get-IssuedRequest.aspx)
* [Get-KeyRecoveryAgentFlag](https://www.sysadmins.lv/projects/pspki/Get-KeyRecoveryAgentFlag.aspx) (Alias: **Get-KRAFlag**)
* [Get-ObjectIdentifier](https://www.sysadmins.lv/projects/pspki/Get-ObjectIdentifier.aspx) (Alias: **oid**)
* [Get-ObjectIdentifierEx](https://www.sysadmins.lv/projects/pspki/Get-ObjectIdentifierEx.aspx) (Alias: **oid2**)
* [Get-OnlineResponderAcl](https://www.sysadmins.lv/projects/pspki/Get-OnlineResponderAcl.aspx) (Alias: **Get-OCSPACL**)
* [Get-OnlineResponderRevocationConfiguration](https://www.sysadmins.lv/projects/pspki/Get-OnlineResponderRevocationConfiguration.aspx)
* [Get-PendingRequest](https://www.sysadmins.lv/projects/pspki/Get-PendingRequest.aspx)
* [Get-PolicyModuleFlag](https://www.sysadmins.lv/projects/pspki/Get-PolicyModuleFlag.aspx)
* [Get-RequestArchivedKey](https://www.sysadmins.lv/projects/pspki/Get-RequestArchivedKey.aspx)
* [Get-RevokedRequest](https://www.sysadmins.lv/projects/pspki/Get-RevokedRequest.aspx)
* [Import-LostCertificate](https://www.sysadmins.lv/projects/pspki/Import-LostCertificate.aspx)
* [Install-CertificateResponse](https://www.sysadmins.lv/projects/pspki/Install-CertificateResponse.aspx)
* [New-SelfSignedCertificateEx](https://www.sysadmins.lv/projects/pspki/New-SelfSignedCertificateEx.aspx)
* [Ping-ICertInterface](https://www.sysadmins.lv/projects/pspki/Ping-ICertInterface.aspx)
* [Publish-CRL](https://www.sysadmins.lv/projects/pspki/Publish-CRL.aspx)
* [Receive-Certificate](https://www.sysadmins.lv/projects/pspki/Receive-Certificate.aspx)
* [Register-ObjectIdentifier](https://www.sysadmins.lv/projects/pspki/Register-ObjectIdentifier.aspx)
* [Remove-AdCertificate](https://www.sysadmins.lv/projects/pspki/Remove-AdCertificate.aspx)
* [Remove-AdCertificateRevocationList](https://www.sysadmins.lv/projects/pspki/Remove-AdCertificateRevocationList.aspx) (Alias: **Remove-AdCrl**)
* [Remove-AdcsDatabaseRow](https://www.sysadmins.lv/projects/pspki/Remove-AdcsDatabaseRow.aspx) (Alias: **Remove-Request**)
* [Remove-AuthorityInformationAccess](https://www.sysadmins.lv/projects/pspki/Remove-AuthorityInformationAccess.aspx) (Alias: **Remove-AIA**)
* [Remove-CAKRACertificate](https://www.sysadmins.lv/projects/pspki/Remove-CAKRACertificate.aspx)
* [Remove-CATemplate](https://www.sysadmins.lv/projects/pspki/Remove-CATemplate.aspx)
* [Remove-CertificatePrivateKey](https://www.sysadmins.lv/projects/pspki/Remove-CertificatePrivateKey.aspx)
* [Remove-CertificateTemplate](https://www.sysadmins.lv/projects/pspki/Remove-CertificateTemplate.aspx)
* [Remove-CertificateTemplateAcl](https://www.sysadmins.lv/projects/pspki/Remove-CertificateTemplateAcl.aspx)
* [Remove-CertificationAuthorityAcl](https://www.sysadmins.lv/projects/pspki/Remove-CertificationAuthorityAcl.aspx) (Alias: **Remove-CAAccessControlEntry Remove-CAACL**)
* [Remove-CRLDistributionPoint](https://www.sysadmins.lv/projects/pspki/Remove-CRLDistributionPoint.aspx) (Alias: **Remove-CDP**)
* [Remove-ExtensionList](https://www.sysadmins.lv/projects/pspki/Remove-ExtensionList.aspx)
* [Remove-OnlineResponderAcl](https://www.sysadmins.lv/projects/pspki/Remove-OnlineResponderAcl.aspx) (Alias: **Remove-OCSPACL**)
* [Remove-OnlineResponderArrayMember](https://www.sysadmins.lv/projects/pspki/Remove-OnlineResponderArrayMember.aspx)
* [Remove-OnlineResponderLocalCrlEntry](https://www.sysadmins.lv/projects/pspki/Remove-OnlineResponderLocalCrlEntry.aspx)
* [Remove-OnlineResponderRevocationConfiguration](https://www.sysadmins.lv/projects/pspki/Remove-OnlineResponderRevocationConfiguration.aspx)
* [Restart-CertificationAuthority](https://www.sysadmins.lv/projects/pspki/Restart-CertificationAuthority.aspx)
* [Restart-OnlineResponder](https://www.sysadmins.lv/projects/pspki/Restart-OnlineResponder.aspx)
* [Restore-CertificateRevocationListFlagDefault](https://www.sysadmins.lv/projects/pspki/Restore-CertificateRevocationListFlagDefault.aspx) (Alias: **Restore-CRLFlagDefault**)
* [Restore-KeyRecoveryAgentFlagDefault](https://www.sysadmins.lv/projects/pspki/Restore-KeyRecoveryAgentFlagDefault.aspx) (Alias: **Restore-KRAFlagDefault**)
* [Restore-PolicyModuleFlagDefault](https://www.sysadmins.lv/projects/pspki/Restore-PolicyModuleFlagDefault.aspx)
* [Revoke-Certificate](https://www.sysadmins.lv/projects/pspki/Revoke-Certificate.aspx)
* [Set-AuthorityInformationAccess](https://www.sysadmins.lv/projects/pspki/Set-AuthorityInformationAccess.aspx) (Alias: **Set-AIA**)
* [Set-CACryptographyConfig](https://www.sysadmins.lv/projects/pspki/Set-CACryptographyConfig.aspx)
* [Set-CAKRACertificate](https://www.sysadmins.lv/projects/pspki/Set-CAKRACertificate.aspx)
* [Set-CATemplate](https://www.sysadmins.lv/projects/pspki/Set-CATemplate.aspx)
* [Set-CertificateExtension](https://www.sysadmins.lv/projects/pspki/Set-CertificateExtension.aspx)
* [Set-CertificateTemplateAcl](https://www.sysadmins.lv/projects/pspki/Set-CertificateTemplateAcl.aspx)
* [Set-CertificateValidityPeriod](https://www.sysadmins.lv/projects/pspki/Set-CertificateValidityPeriod.aspx)
* [Set-CertificationAuthorityAcl](https://www.sysadmins.lv/projects/pspki/Set-CertificationAuthorityAcl.aspx) (Alias: **Set-CAACL Set-CASecurityDescriptor**)
* [Set-CRLDistributionPoint](https://www.sysadmins.lv/projects/pspki/Set-CRLDistributionPoint.aspx) (Alias: **Set-CDP**)
* [Set-CRLValidityPeriod](https://www.sysadmins.lv/projects/pspki/Set-CRLValidityPeriod.aspx)
* [Set-ExtensionList](https://www.sysadmins.lv/projects/pspki/Set-ExtensionList.aspx)
* [Set-OnlineResponderAcl](https://www.sysadmins.lv/projects/pspki/Set-OnlineResponderAcl.aspx) (Alias: **Set-OCSPACL**)
* [Set-OnlineResponderProperty](https://www.sysadmins.lv/projects/pspki/Set-OnlineResponderProperty.aspx)
* [Set-OnlineResponderRevocationConfiguration](https://www.sysadmins.lv/projects/pspki/Set-OnlineResponderRevocationConfiguration.aspx)
* [Show-Certificate](https://www.sysadmins.lv/projects/pspki/Show-Certificate.aspx)
* [Show-CertificateRevocationList](https://www.sysadmins.lv/projects/pspki/Show-CertificateRevocationList.aspx) (Alias: **Show-CRL**)
* [Show-CertificateTrustList](https://www.sysadmins.lv/projects/pspki/Show-CertificateTrustList.aspx) (Alias: **Show-CTL**)
* [Start-CertificationAuthority](https://www.sysadmins.lv/projects/pspki/Start-CertificationAuthority.aspx)
* [Start-OnlineResponder](https://www.sysadmins.lv/projects/pspki/Start-OnlineResponder.aspx)
* [Stop-CertificationAuthority](https://www.sysadmins.lv/projects/pspki/Stop-CertificationAuthority.aspx)
* [Stop-OnlineResponder](https://www.sysadmins.lv/projects/pspki/Stop-OnlineResponder.aspx)
* [Submit-CertificateRequest](https://www.sysadmins.lv/projects/pspki/Submit-CertificateRequest.aspx)
* [Test-WebServerSSL](https://www.sysadmins.lv/projects/pspki/Test-WebServerSSL.aspx)
* [Unregister-ObjectIdentifier](https://www.sysadmins.lv/projects/pspki/Unregister-ObjectIdentifier.aspx)

