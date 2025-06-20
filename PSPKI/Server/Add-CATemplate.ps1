function Add-CATemplate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.CATemplate')]
[CmdletBinding(DefaultParameterSetName = "__DisplayName")]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
        [PKI.CertificateServices.CATemplate[]]$InputObject,
        [Parameter(Mandatory = $true,ParameterSetName = "__DisplayName")]
        [String[]]$DisplayName,
        [Parameter(Mandatory = $true,ParameterSetName = "__Name")]
        [String[]]$Name,
        [Parameter(Mandatory = $true,ParameterSetName = "__Template")]
        [PKI.CertificateTemplates.CertificateTemplate[]]$Template
    )

    begin {
        Assert-CommandRequirement $PREREQ_ADDS, $PREREQ_RSAT -ErrorAction Stop
    }

    process {
        foreach ($CATemplate in $InputObject) {
            try {
                switch ($PsCmdlet.ParameterSetName) {
                    "__DisplayName" {
                        $Templates = $DisplayName | ForEach-Object {[SysadminsLV.PKI.CertificateTemplates.CertificateTemplateFactory]::CreateFromDisplayNameDs($_)}
                        $CATemplate.AddRange($Templates)
                    }
                    "__Name" {
                        $Templates = $Name | ForEach-Object {[SysadminsLV.PKI.CertificateTemplates.CertificateTemplateFactory]::CreateFromCommonNameDs($_)}
                        $CATemplate.AddRange($Templates)
                    }
                    "__Template" {
                        $CATemplate.AddRange($Template)
                    }
                }
                $CATemplate
            } finally { }
        }
    }
}