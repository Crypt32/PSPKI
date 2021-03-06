function Start-PsFCIV {
<#
.ExternalHelp PsFCIV.Help.xml
#>
[CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [IO.DirectoryInfo]$Path,
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = '__xml')]
        [string]$XML,
        [Parameter(Position = 2)]
        [string]$Include = "*",
        [Parameter(Position = 3)]
        [string[]]$Exclude,
        [ValidateSet("Rename", "Delete")]
        [string]$Action,
        [ValidateSet("Bad", "Locked", "Missed", "New", "Ok", "Unknown", "All")]
        [String[]]$Show,
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [AllowEmptyCollection()]
        [String[]]$HashAlgorithm = "SHA1",
        [switch]$Recurse,
        [switch]$Rebuild,
        [switch]$Quiet,
        [switch]$NoStatistic,
        [Parameter(ParameterSetName = '__online')]
        [switch]$Online
    )

#region C# wrappers
Add-Type @"
using System;
using System.Collections.Generic;
using System.Xml.Serialization;
namespace PsFCIV {
    public class StatTable {
        public List<String> Total = new List<String>();
        public List<String> New = new List<String>();
        public List<String> Ok = new List<String>();
        public List<String> Bad = new List<String>();
        public List<String> Missed = new List<String>();
        public List<String> Locked = new List<String>();
        public List<String> Unknown = new List<String>();
        public int Del;
    }
    public class IntStatTable {
        public Int32 Total { get; set; }
        public Int32 New { get; set; }
        public Int32 Ok { get; set; }
        public Int32 Bad { get; set; }
        public Int32 Missed { get; set; }
        public Int32 Locked { get; set; }
        public Int32 Unknown { get; set; }
        public Int32 Del { get; set; }
    }
    [XmlType(AnonymousType = true)]
    [XmlRoot(Namespace = "", IsNullable = false)]
    public class FCIV {
        public FCIV() { FILE_ENTRY = new List<FCIVFILE_ENTRY>(); }
        
        [XmlElement("FILE_ENTRY")]
        public List<FCIVFILE_ENTRY> FILE_ENTRY { get; set; }
    }
    [XmlType(AnonymousType = true)]
    public class FCIVFILE_ENTRY {
        public FCIVFILE_ENTRY() { }
        public FCIVFILE_ENTRY(string path) { Name = path; }

        [XmlElement("name")]
        public String Name { get; set; }
        public UInt64 Size { get; set; }
        public String TimeStamp { get; set; }
        public String MD5 { get; set; }
        public String SHA1 { get; set; }
        public String SHA256 { get; set; }
        public String SHA384 { get; set; }
        public String SHA512 { get; set; }

        public override Int32 GetHashCode() { return Name.GetHashCode(); }
        public override Boolean Equals(Object other) {
            if (ReferenceEquals(null, other) || other.GetType() != GetType()) { return false; }
            return other.GetType() == GetType() && String.Equals(Name, ((FCIVFILE_ENTRY)other).Name);
        }
    }
}
"@ -Debug:$false -Verbose:$false -ReferencedAssemblies "System.Xml"
Add-Type -AssemblyName System.Xml
#endregion
    # configure preferences
    if ($PSBoundParameters.Verbose) {$VerbosePreference = "continue"}
    if ($PSBoundParameters.Debug) {$DebugPreference = "continue"}
    
    # add DB file to exclusion list
    if (Test-Path -LiteralPath $XML) {
        $XML = (Resolve-Path $XML).ProviderPath
    }
    $Exclude += $XML
    
    # preserving current path
    $oldpath = $pwd.ProviderPath
    if (Test-Path -LiteralPath $path) {
        Set-Location -LiteralPath $path
        if ($pwd.Provider.Name -ne "FileSystem") {
            Set-Location $oldpath
            throw "Specified path is not filesystem path. Try again!"
        }
    } else {throw "Specified path not found."}
    
    # statistic variables
    $sum = $new = New-Object PsFCIV.FCIV
    # creating statistics variable with properties. Each property will contain file names (and paths) with corresponding status.
    $global:stats = New-Object PsFCIV.StatTable
    $script:statcount = New-Object PsFCIV.IntStatTable
    
    # lightweight proxy function for Get-ChildItem cmdlet
    function dirx ([string]$Path, [string]$Filter, [string[]]$Exclude, $Recurse, [switch]$Force) {
        Get-ChildItem @PSBoundParameters -ErrorAction SilentlyContinue | Where-Object {!$_.psiscontainer}
    }	
    # internal function that will check whether the file is locked. All locked files are added to a group with 'Unknown' status.
    function __filelock ($file) {
        $locked = $false
        trap {Set-Variable -name locked -value $true -scope 1; continue}
        $inputStream = New-Object IO.StreamReader $file.FullName
        if ($inputStream) {$inputStream.Close()}
        if ($locked) {
            Write-Verbose "File $($file.Name) is locked. Skipping this file.."
            Write-Debug "File $($file.Name) is locked. Skipping this file.."
            __statcounter $filename Locked
        }
        $locked
    }	
    # internal function to generate UI window with results by using Out-GridView cmdlet.
    function __formatter ($props, $max) {
        $total = @($input)
        foreach ($property in $props) {
            $(for ($n = 0; $n -lt $max; $n++) {
                $total[0] | Select-Object @{n = $property; e = {$_.$property[$n]}}
            }) | Out-GridView -Title "File list by category: $property"
        }
    }
    # internal hasher
    function __hashbytes ($type, $file) {
        $hasher = [Security.Cryptography.HashAlgorithm]::Create($type)
        $inputStream = New-Object IO.StreamReader $file.FullName
        $hashBytes = $hasher.ComputeHash($inputStream.BaseStream)
        $hasher.Clear()
        $inputStream.Close()
        $hashBytes
    }
    # internal function which reads the XML file (if exist).
    function __fromxml ($xml) {
    # reading existing XML file and selecting required properties
        if (!(Test-Path -LiteralPath $XML)) {return New-Object PsFCIV.FCIV}
        try {
            $fs = New-Object IO.FileStream $XML, "Open"
            $xmlser = New-Object System.Xml.Serialization.XmlSerializer ([Type][PsFCIV.FCIV])
            $sum = $xmlser.Deserialize($fs)
            $fs.Close()
            $sum
        } catch {
            Write-Error -Category InvalidData -Message "Input XML file is not valid FCIV XML file."
        } finally {
            if ($fs -ne $null) {$fs.Close()}
        }
        
    }
    # internal xml writer
    function __writexml ($sum) {
        if ($sum.FILE_ENTRY.Count -eq 0) {
            Write-Verbose "There is no data to write to XML database."
            Write-Debug "There is no data to write to XML database."
        } else {
            Write-Debug "Preparing to DataBase file creation..."
            try {
                $fs = New-Object IO.FileStream $XML, "Create"
                $xmlser = New-Object System.Xml.Serialization.XmlSerializer ([Type][PsFCIV.FCIV])
                $xns = New-Object System.Xml.Serialization.XmlSerializerNamespaces
                $xns.Add("", "")
                $xmlser.Serialize($fs, $sum, $xns)
            } finally {
                if ($fs -ne $null) {$fs.Close()}
            }
            Write-Debug "DataBase file created..."
        }
    }
    # internal function to create XML entry object for a file.
    function __makeobject ($file, [switch]$NoHash, [switch]$hex) {
        Write-Debug "Starting object creation for '$($file.FullName)'..."
        $object = New-Object PsFCIV.FCIVFILE_ENTRY
        $object.Name = $file.FullName -replace [regex]::Escape($($pwd.ProviderPath + "\"))
        $object.Size = $file.Length
        # use culture-invariant date/time format.
        $object.TimeStamp = "$($file.LastWriteTime.ToUniversalTime())"
        if (!$NoHash) {
        # calculating appropriate hash and convert resulting byte array to a Base64 string
            foreach ($hash in "MD5", "SHA1", "SHA256", "SHA384", "SHA512") {
                if ($HashAlgorithm -contains $hash) {
                    Write-Debug "Calculating '$hash' hash..."
                    $hashBytes = __hashbytes $hash $file
                    if ($hex) {
                        $object.$hash = -join ($hashBytes | Foreach-Object {"{0:X2}" -f $_})
                    } else {
                        Write-Debug ("Calculated hash value: " + (-join ($hashBytes | Foreach-Object {"{0:X2}" -f $_})))
                        $object.$hash = [System.Convert]::ToBase64String($hashBytes)
                    }
                }
            }
        }
        Write-Debug "Object created!"
        $object
    }	
    # internal function that calculates current file hash and formats it to an octet string (for example, B926D7416E8235E6F94F756E9F3AE2F33A92B2C4).
    function __precheck ($entry, $file, $HashAlgorithm) {
        if ($HashAlgorithm.Length -gt 0) {
            $SelectedHash = $HashAlgorithm
        } else {
            :outer foreach ($hash in "SHA512", "SHA384", "SHA256", "SHA1", "MD5") {
                if ($entry.$hash) {$SelectedHash = $hash; break outer}
            }
        }
        Write-Debug "Selected hash: $SelectedHash"
        -join ($(__hashbytes $SelectedHash $file) | ForEach-Object {"{0:X2}" -f $_})
        $SelectedHash
    }
    # process -Action parameter to perform an action against bad file (if actual file properties do not match the record in XML).
    function __takeaction ($file, $Action) {
        switch ($Action) {
            "Rename" {Rename-Item $file $($file.FullName + ".bad")}
            "Delete" {Remove-Item $file -Force}
        }
    }	
    # core file verification function.
    function __checkfiles ($entry, $file, $Action) {
        if (($file.Length -eq $entry.Size) -and ("$($file.LastWriteTime.ToUniversalTime())" -eq $entry.TimeStamp)) {
            $hexhash = __precheck $entry $file $HashAlgorithm
            $ActualHash = -join ([Convert]::FromBase64String($entry.($hexhash[1])) | ForEach-Object {"{0:X2}" -f $_})
            if (!$ActualHash) {
                Write-Verbose "XML database entry does not contain '$($hexhash[1])' hash value for the entry '$($entry.Name)'."
                __statcounter $entry.Name Unknown
                return
            } elseif ($ActualHash -eq $hexhash[0]) {
                Write-Debug "File hash: $ActualHash"
                Write-Verbose "File '$($file.Name)' is ok."
                __statcounter $entry.Name Ok
                return
            } else {
                Write-Debug "File '$($file.Name)' failed hash verification.
                    Expected hash: $hexhash
                    Actual hash: $ActualHash"
                __statcounter $entry.Name Bad
                if ($Action) {__takeaction $file $Action}
            }
        } else {
            Write-Verbose "File '$($file.FullName)' size or Modified Date/Time mismatch."
            Write-Debug "Expected file size is: $($entry.Size) byte(s), actual size is: $($file.Length) byte(s)."
            Write-Debug "Expected file modification time is: $($entry.TimeStamp), actual file modification time is: $($file.LastWriteTime.ToUniversalTime())"
            __statcounter $entry.Name Bad
            if ($Action) {__takeaction $file $Action}
        }
    }
    # internal function to calculate resulting statistics and show if if necessary.	
    function __stats {
    # if -Show parameter is presented we display selected groups (Total, New, Ok, Bad, Missed, Unknown)
        if ($show -and !$NoStatistic) {
            if ($Show -eq "All" -or $Show.Contains("All")) {
                $global:stats | __formatter "Bad", "Locked", "Missed", "New", "Ok", "Unknown" $script:statcount.Total
            } else {
                $global:stats | Select-Object $show | __formatter $show $script:statcount.Total
            }			
        }
        # script work in numbers
        if (!$Quiet) {
            Write-Host ----------------------------------- -ForegroundColor Green
            if ($Rebuild) {
                Write-Host "Total entries processed      :" $script:statcount.Total -ForegroundColor Cyan
                Write-Host "Total removed unused entries :" $script:statcount.Del -ForegroundColor Yellow
                Write-Host "Total new added files        :" $script:statcount.New -ForegroundColor Green
                Write-Host "Total locked files           :" $script:statcount.Locked -ForegroundColor Yellow
            } else {
                Write-Host "Total files processed      :" $script:statcount.Total -ForegroundColor Cyan
                Write-Host "Total new added files      :" $script:statcount.New -ForegroundColor Green
                Write-Host "Total good files           :" $script:statcount.Ok -ForegroundColor Green
                Write-Host "Total bad files            :" $script:statcount.Bad -ForegroundColor Red
                Write-Host "Total unknown status files :" $script:statcount.Unknown -ForegroundColor Yellow
                Write-Host "Total missing files        :" $script:statcount.Missed -ForegroundColor Yellow
                Write-Host "Total locked files         :" $script:statcount.Locked -ForegroundColor Yellow
            }
            Write-Host ----------------------------------- -ForegroundColor Green
        }
        # restore original variables
        Set-Location -LiteralPath $oldpath
        $exit = 0
        # create exit code depending on check status
        if ($Rebuild) {$exit = [int]::MaxValue} else {
            if ($script:statcount.Bad -ne 0) {$exit += 1}
            if ($script:statcount.Missed -ne 0) {$exit += 2}
            if ($script:statcount.Unknown -ne 0) {$exit += 4}
            if ($script:statcount.Locked -ne 0) {$exit += 8}
        }
        if ($Quiet) {exit $exit}
    }
    # internal function to update statistic counters.
    function __statcounter ($filename, $status) {
        $script:statcount.$status++
        $script:statcount.Total++
        if (!$NoStatistic) {
            $global:stats.$status.Add($filename)
        }
    }
    if ($Online) {
        Write-Debug "Online mode ON"
        dirx -Path .\* -Filter $Include -Exclude $Exclude $Recurse -Force | ForEach-Object {
            Write-Verbose "Perform file '$($_.fullName)' checking."
            $file = Get-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
            if (__filelock $file) {return}
            __makeobject $file -hex
        }
        return
    }

    <#
    in this part we perform XML file update by removing entries for non-exist files and
    adding new entries for files that are not in the database.
    #>
    if ($Rebuild) {
        Write-Debug "Rebuild mode ON"
        if (Test-Path -LiteralPath $xml) {
            $old = __fromxml $xml
        } else {
            Set-Location $oldpath
            throw "Unable to find XML file. Please, run the command without '-Rebuild' switch."
        }
        $interm = New-Object PsFCIV.FCIV
        # use foreach-object instead of where-object to keep original types.
        Write-Verbose "Perform DB file cleanup from non-existent items."
        $old.FILE_ENTRY | ForEach-Object {
            if ((Test-Path -LiteralPath $_.Name)) {
                if ($_.Name -eq $xml) {
                    Write-Debug "File '$($_.Name)' is DB file. Removed."
                    $script:statcount.Del++
                } else {
                    $interm.FILE_ENTRY.Add($_)
                }
            } else {
                Write-Debug "File '$($_.Name)' does not exist. Removed."
                $script:statcount.Del++
            }
        }
        
        $script:statcount.Total = $old.FILE_ENTRY.Count - $interm.FILE_ENTRY.Count
        dirx -Path .\* -Filter $Include -Exclude $Exclude $Recurse -Force | ForEach-Object {
            if ($_.FullName -eq $XML) {
                return
            }
            Write-Verbose "Perform file '$($_.FullName)' checking."
            $file = Get-Item -LiteralPath $_.FullName -Force
            if (__filelock $file) {return}
            $filename = $file.FullName -replace [regex]::Escape($($pwd.providerpath + "\"))
            if ($interm.FILE_ENTRY.Contains((New-Object PsFCIV.FCIVFILE_ENTRY $filename))) {
                Write-Verbose "File '$filename' already exist in XML database. Skipping."
                return
            } else {
                $new.FILE_ENTRY.Add((__makeobject $file))
                Write-Verbose "File '$filename' is added."
                __statcounter $filename New
            }
        }
        $interm.FILE_ENTRY.AddRange($new.FILE_ENTRY)
        __writexml $interm
        __stats
        return
    }
    
    # this part contains main routine
    $sum = __fromxml $xml
    <#
    check XML file format. If Size property of the first element is zero, then the file was generated by
    original FCIV.exe tool. In this case we transform existing XML to a new PsFCIV format by adding new
    properties. Each record is checked against hashes stored in the source XML file. If hash check fails,
    an item is removed from final XML.
    #>
    if ($sum.FILE_ENTRY.Count -gt 0 -and $sum.FILE_ENTRY[0].Size -eq 0) {
        # 
        if ($PSBoundParameters.ContainsKey("HashAlgorithm")) {
            $HashAlgorithm = $HashAlgorithm[0].ToUpper()
        } else {
            $HashAlgorithm = @()
        }
        Write-Debug "FCIV (compatibility) mode ON"
        if ($HashAlgorithm -and $HashAlgorithm -notcontains "sha1" -and $HashAlgorithm -notcontains "md5") {
            throw "Specified hash algorithm (or algorithms) is not supported. For native FCIV source, use MD5 and/or SHA1."
        }
        for ($index = 0; $index -lt $sum.FILE_ENTRY.Count; $index++) {
            Write-Verbose "Perform file '$($sum.FILE_ENTRY[$index].Name)' checking."
            $filename = $sum.FILE_ENTRY[$index].Name
            # check if the path is absolute and matches current path. If the path is absolute and does not belong to
            # current path -- skip this entry.
            if ($filename.Contains(":") -and $filename -notmatch [regex]::Escape($pwd.ProviderPath)) {return}
            # if source file name record contains absolute path, and belongs to the current pathe,
            # just strip base path. New XML format uses relative paths only.
            if ($filename.Contains(":")) {$filename = $filename -replace ([regex]::Escape($($pwd.ProviderPath + "\")))}
            # Test if the file exist. If the file does not exist, skip the current entry and process another record.
            if (!(Test-Path -LiteralPath $filename)) {
                Write-Verbose "File '$filename' not found. Skipping."
                __statcounter $filename Missed
                return
            }
            # get file item and test if it is not locked by another application
            $file = Get-Item -LiteralPath $filename -Force -ErrorAction SilentlyContinue
            if (__filelock $file) {return}
            # create new-style entry record that stores additional data: file length and last modification timestamp.
            $entry = __makeobject $file -NoHash
            $entry.Name = $filename
            # process current hash entries and copy required hash values to a new entry object.
            "SHA1", "MD5" | ForEach-Object {$entry.$_ = $sum.FILE_ENTRY[$index].$_}
            $sum.FILE_ENTRY[$index] = $entry
            __checkfiles $newentry $file $Action
        }
        # we are done. Overwrite XML, display stats and exit.
        __writexml $sum
        # display statistics and exit right now.
        __stats
    }
    # if XML file exist, proccess and check all records. XML file will not be modified.
    if ($sum.FILE_ENTRY.Count -gt 0) {
        Write-Debug "Native PsFCIV mode ON"
        # this part is executed only when we want to process certain file. Wildcards are not allowed.
        if ($Include -ne "*") {
            $sum.FILE_ENTRY | Where-Object {$_.Name -like $Include} | ForEach-Object {
                Write-Verbose "Perform file '$($_.Name)' checking."
                $entry = $_
                # calculate the hash if the file exist.
                if (Test-Path -LiteralPath $entry.Name) {
                    # and check file integrity
                    $file = Get-Item -LiteralPath $entry.Name -Force -ErrorAction SilentlyContinue
                    __checkfiles $entry $file $Action
                } else {
                    # if there is no record for the file, skip it and display appropriate message
                    Write-Verbose "File '$filename' not found. Skipping."
                    __statcounter $entry.Name Missed
                }
            }
        } else {
            $sum.FILE_ENTRY | ForEach-Object {
                <#
                to process files only in the current directory (without subfolders), we remove items
                that contain slashes from the process list and continue regular file checking.
                #>
                if (!$Recurse -and $_.Name -match "\\") {return}
                Write-Verbose "Perform file '$($_.Name)' checking."
                $entry = $_
                if (Test-Path -LiteralPath $entry.Name) {
                    $file = Get-Item -LiteralPath $entry.Name -Force -ErrorAction SilentlyContinue
                    __checkfiles $entry $file $Action
                } else {
                    Write-Verbose "File '$($entry.Name)' not found. Skipping."
                    __statcounter $entry.Name Missed
                }
            }
        }
    } else {
        # if there is no existing XML DB file, start from scratch and create a new one.
        Write-Debug "New XML mode ON"

        dirx -Path .\* -Filter $Include -Exclude $Exclude $Recurse -Force | ForEach-Object {
             Write-Verbose "Perform file '$($_.fullName)' checking."
             $file = Get-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
             if (__filelock $file) {return}
             $entry = __makeobject $file
             $sum.FILE_ENTRY.Add($entry)
             __statcounter $entry.Name New
        }
        __writexml $sum
    }
    __stats
}