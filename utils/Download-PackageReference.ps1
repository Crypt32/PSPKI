$ErrorActionPreference = "Stop"
$PackageMap = @{
    "SysadminsLV.Asn1Parser"            = "1.3.0","net472"
    "SysadminsLV.PKI"                   = "4.4.0","net472"
    "SysadminsLV.PKI.OcspClient"        = "4.4.0","net472"
    "SysadminsLV.PKI.Win"               = "4.4.0","net472"
    "System.Security.Cryptography.Pkcs" = "10.0.5","net462"
}

Push-Location $PSScriptRoot
$DestPath = gi "..\PSPKI\Library"
function Download-PSPKIPackage {
    del $DestPath -Recurse -Force
    md $DestPath -Force | Out-Null
    foreach ($Key in $PackageMap.Keys) {
        $WorkDir = md (Join-Path $PSScriptRoot "_work") -Force
        $url = "https://www.nuget.org/api/v2/package/{0}/{1}" -f $Key, $PackageMap[$Key][0]
        $nupkgPath = Join-Path $WorkDir.FullName "package.zip"
        Invoke-WebRequest -Uri $url -OutFile $nupkgPath
        Expand-Archive -Path $nupkgPath -DestinationPath $WorkDir
        $dllPath = Join-Path $WorkDir.FullName ("lib\{0}" -f $PackageMap[$Key][1])
        dir $dllPath -Exclude *.xml | copy -Destination $DestPath
        del $WorkDir -Recurse -Force
    }
}

Download-PSPKIPackage
Pop-Location