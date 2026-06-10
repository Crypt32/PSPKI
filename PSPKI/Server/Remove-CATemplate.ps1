function Remove-CATemplate {
<#
.ExternalHelp PSPKI.Help.xml
#>
[OutputType('PKI.CertificateServices.CATemplate')]
[CmdletBinding(DefaultParameterSetName = "__DisplayName")]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelinebyPropertyName = $true)]
        [PKI.CertificateServices.CATemplate[]]$InputObject,
        [Parameter(Mandatory = $true,ParameterSetName = "__Name")]
        [String[]]$Name,
        [Parameter(Mandatory = $true,ParameterSetName = "__DisplayName")]
        [String[]]$DisplayName,
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
                    "__Name" {
                        if ($Name -contains "*") {
                            $CATemplate.Clear()
                        } else {
                            $Templates = $Name | ForEach-Object {[SysadminsLV.PKI.CertificateTemplates.CertificateTemplateFactory]::CreateFromCommonNameDs($_)}
                            $CATemplate.RemoveRange($Templates)
                        }
                    }
                    "__DisplayName" {
                        if ($DisplayName -contains "*") {
                            $CATemplate.Clear()
                        } else {
                            $Templates = $DisplayName | ForEach-Object {[SysadminsLV.PKI.CertificateTemplates.CertificateTemplateFactory]::CreateFromDisplayNameDs($_)}
                            $CATemplate.RemoveRange($Templates)
                        }
                    }
                    "__Template" {
                        $CATemplate.RemoveRange($Template)
                    }
                }
                $CATemplate
            } finally { }
        }
    }
}