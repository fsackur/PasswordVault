<#
    .NOTES
    Heads up! You may be governed by corporate policy on where secret information may be stored! It is the user's
    responsibility to determine applicability. No warranty is provided.

    In a situation where you require passwords in plaintext, for example to provide to an RDP application, the
    Windows Password Vault or Credential Manager is probably the best choice.

    Windows 8.1 introduces the Windows.Security.Credentials.PasswordVault class, but previous versions only offer
    cmdkey natively.

    This module is intended to wrap both methods to provide a platform-agnostic way of storing and retrieving
    credentials. Credentials are visible (although not plaintext passwords) in the Credential Manager applet.
    On the newer platform, credentials are stored in the "Web Credentials" section of the applet; on the older
    platform, credentials are stored in the "generic" subsection.

    Why not always use compatibility mode? Because I'm adding backward compatibility to code I've already written,
    and because the backward compatibility is a lot of code and relatively shonky, so I'm planning lifecycle. 
    
    I have made a point of implementing all the methods of the PasswordVault class as functions. However, the "FindAll"
    methods make backward compatibility tricky. Use these ones with caution.

    Beware: return types differ between compatibility modes. PasswordVault methods return a PasswordCredential object
    that cannot be casted to PSCredential. This object is not available in backward compatibility mode, so I return a
    PSObject instead. To improve this in Get-PasswordVaultEntry, there is an -AsPSCredential switch which forces a 
    PSCredential to be returned in all cases.

    Beware: Win7 returns an obscured password. Use the -AsPlaintext switch to return plaintext regardless of OS version.

    The functions exposed are:
        Add-PasswordVaultEntry ([string]$Username, [string]$Password, [string]$Resource)
        Add-PasswordVaultEntry ([Windows.Security.Credentials.PasswordCredential]$Credential)
        Remove-PasswordVaultEntry ([string]$Username, [string]$Resource)
        Remove-PasswordVaultEntry ([Windows.Security.Credentials.PasswordCredential]$Credential)
        Find-PasswordVaultEntry ([string]$Username)
        Find-PasswordVaultEntry ([string]$Resource)
        Find-PasswordVaultEntry ([string]$Username, [string]$Resource)
        Get-PasswordVaultEntry ([string]$Resource, [string]$Username)
        Get-PasswordVaultEntry ()
        ConvertTo-Plaintext ([SecureString]$SecureString)

    Author: Freddie Sackur
    Github: https://github.rackspace.com/mich8638/Jimmy
    Minimum OS: Win7
    Minimum PoSh: 3.0
    Date: 15/2/16
    Rev:  0.3
    Approved by: 
#>

#requires -Version 3

#region Determine mode: native PasswordVault class or cmdkey cmdline utility
$Global:PasswordVaultCompatibilityMode = $false
$ErrorActionPreferencePop = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
try {
    [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
} catch [System.Management.Automation.RuntimeException] {
    #Class only exists on Windows 8 and above
    if ($_ -like "Unable to find type *") {
        $Global:PasswordVaultCompatibilityMode = $true
    } else {throw $_}
}
$ErrorActionPreference = $ErrorActionPreferencePop
Write-Verbose "Password Vault compatibility mode: $PasswordVaultCompatibilityMode"
#endregion



function Add-PasswordVaultEntry {
    <#
        .SYNOPSIS
        Securely stores a credential in the Windows Password Vault or Credential Manager

        .DESCRIPTION
        Securely stores a credential in the Windows Password Vault or Credential Manager. The password vault is keyed to the user, so that credentials stored in it can only be retrieved by the user account that stored them (notwithstanding any vulnerabilities that may exist).

        On Win8+, this function wraps the Add() method of Windows.Security.Credentials.PasswordVault. On Win7 and below, it wraps cmdkey to provide equivalent functionality.

        On Win8 and above, credentials stored here can be viewed in the Web Credentials section of the Password Vault control panel applet. On Win7 and below, they can be seen in Credential Manager but the password cannot be revealed. In either case, Get-PasswordVaultEntry can return the credential in plaintext.

        If the credential exceeds the maximum length, it is split into chunks. This is common with SAML tokens, which can be large, on Win7. Get-PasswordVaultEntry reassembles the chunks. This operation is transparent to the user, but noticable in the Password Vault applet.

        .PARAMETER Username
        The username of the credential to be stored

        .PARAMETER Password
        The password of the credential to be stored

        .PARAMETER Resource
        The resource that the credential is for. For example, if the credential is for a web portal, this would be the URL.
        
        For CLI usage, the resource parameter can be considered a "Name" and can be anything. "Name" is an alias for this parameter.

        .Parameter Credential
        This accepts a Windows.Security.Credentials.PasswordCredential object, on Win8+. This is not the same as a PSCredential. This parameter is included only in order to completely expose the overloads of the underlying class in Win8+

        .EXAMPLE
        Add-PasswordVaultEntry -Username "bob22@aol.com" -Password "hunter2" -Resource "http://bankofbob.com/login.jsp"

        Stores a credential for the bankofbob.com website

        .EXAMPLE
        Add-PasswordVaultEntry -Username "CONTOSO\Bob" -Password "hunter2" -Name "PVScript#00034"

        Stores a credential that can be retrieved using the identifier "PVScript#00034"

        .EXAMPLE
        $PVCredential = New-Object Windows.Security.Credentials.PasswordCredential("PVScript#00034", "CONTOSO\bob", "hunter2")
        Add-PasswordVaultEntry -Credential $PVCredential

        On Windows 8 or Server 2012 and above, stores a credential that can be retrieved using the identifier "PVScript#00034"
    #>

    [CmdletBinding(DefaultParameterSetName='UsernameAndResource')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='UsernameAndResource')]
        [string]$Username,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='UsernameAndResource')]
        [string]$Password,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=2, ParameterSetName='UsernameAndResource')]
        [Alias("Name")]
        [string]$Resource,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='Credential')]
        [ValidateScript({$_.UserName -and $_.Resource -and $_.Password})]
        $Credential  #this expects a [Windows.Security.Credentials.PasswordCredential] but I can't define the type or I break Win7 compatibility.
    )

    if ($PasswordVaultCompatibilityMode) {
        
        if ($PSCmdlet.ParameterSetName -like "Credential") {
            Add-PVCMEntry -Username $Credential.UserName -Password $Credential.Password -Resource $Credential.Resource
        } else {
            Add-PVCMEntry @PSBoundParameters
        }

    } else {
    
        Write-Debug "Removing Password Vault entry with username $Username and resource $Resource"
        $Vault = Get-PasswordVault

        if ($PSCmdlet.ParameterSetName -notlike "Credential") {
            $Credential = New-Object Windows.Security.Credentials.PasswordCredential -Property @{UserName=$Username; Resource=$Resource; Password=$Password}
        }
        $Vault.Add($Credential)

    }
}

function Remove-PasswordVaultEntry {
    <#
        .SYNOPSIS
        Removes a credential from the Windows Password Vault or Credential Manager

        .DESCRIPTION
        Removes a credential from the Windows Password Vault or Credential Manager. You must run this command as the same user that stored the credential.

        On Win8+, this function wraps the Remove() method of Windows.Security.Credentials.PasswordVault. On Win7 and below, it wraps cmdkey to provide equivalent functionality.

        .PARAMETER Username
        The username of the credential to be removed

        .PARAMETER Resource
        The resource or name of the credential to be stored. "Name" is an alias for this parameter.

        .Parameter Credential
        This accepts a Windows.Security.Credentials.PasswordCredential object, on Win8+. This is not the same as a PSCredential. This parameter is included only in order to completely expose the overloads of the underlying class in Win8+

        .EXAMPLE
        Remove-PasswordVaultEntry -Username "bob22@aol.com" -Resource "http://bankofbob.com/login.jsp"

        Removes the credential for the bankofbob.com website with username "bob22@aol.com"

        .EXAMPLE
        $PVCredential = New-Object Windows.Security.Credentials.PasswordCredential("PVScript#00034", "CONTOSO\bob", "hunter2")
        Remove-PasswordVaultEntry -Credential $PVCredential

        On Windows 8 or Server 2012 and above, removes the credential with identifier "PVScript#00034" and username "CONTOSO\bob"
    #>

    [CmdletBinding(DefaultParameterSetName='UsernameAndResource')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='UsernameAndResource')]
        [string]$Username,
        
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='UsernameAndResource')]
        [Alias("Name")]
        [string]$Resource,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='Credential')]
        [ValidateScript({$_.UserName -and $_.Resource -and $_.Password})]
        $Credential  #this expects a [Windows.Security.Credentials.PasswordCredential] but I can't define the type or I break Win7 compatibility.
    )

    if ($PasswordVaultCompatibilityMode) {
        
        if ($PSCmdlet.ParameterSetName -like "Credential") {
            Remove-PVCMEntry -Username $Credential.UserName -Resource $Credential.Resource
        } else {
            Remove-PVCMEntry @PSBoundParameters
        }

    } else {
    
        Write-Debug "Removing Password Vault entry with username $Username and resource $Resource"
        $Vault = Get-PasswordVault

        try {
            if ($PSCmdlet.ParameterSetName -notlike "Credential") {$Credential = $Vault.Retrieve($Resource, $Username)}
            $Vault.Remove($Credential)
        } catch [System.Management.Automation.MethodInvocationException] {
            if ($_ -like "*Element not found*") {Write-Debug "Entry was not present in Credential Manager"} else {throw $_}
        }

    }
}

function Find-PasswordVaultEntry {
    <#
        .SYNOPSIS
        Retrieves the username and resource name parts of a credential from the Windows Password Vault or Credential Manager

        .DESCRIPTION
        Retrieves the username and resource name parts of a credential - in other words, the non-secure parts - from the Windows Password Vault or Credential Manager. You must run this command as the same user that stored the credential.

        On Win8+, only Web Credentials are retrieved. On Win7, only generic credentials are retrieved. Credentials stored with Add-PasswordVaultEntry are always of these types, but credentials stored by the user in other ways may not be retrievable.

        On Win8+, this function wraps the FindAllByUsername() and FindAllByResource() methods of Windows.Security.Credentials.PasswordVault. On Win7 and below, it wraps cmdkey to provide equivalent functionality.

        THERE ARE BACKWARD COMPATIBILITY ISSUES WITH WIN 7 AND BELOW. Since version-agnosticism is a goal of this module, use of this function is deprecated in favour of Get-PasswordVaultEntry, which is normally more useful.
        

        .PARAMETER Username
        The username of the credential

        .PARAMETER Resource
        The resource that the credential is for. For example, if the credential is for a web portal, this would be the URL.
        
        For CLI usage, the resource parameter can be considered a "Name" and can be anything. "Name" is an alias for this parameter.

        .EXAMPLE
        Find-PasswordVaultEntry -Username "bob22@aol.com"

        Finds all credentials with username "bob22@aol.com"

        .EXAMPLE
        Find-PasswordVaultEntry -Resource "PVScript#00034"

        Finds all credentials with the resource identifier "PVScript#00034"
    #>

    [CmdletBinding(DefaultParameterSetName='Resource')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='Username')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='UsernameAndResource')]
        [string]$Username,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='Resource')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='UsernameAndResource')]
        [Alias("Name")]
        [string]$Resource
    )

    Write-Warning "Backward compatibility issues exist with Find-PasswordVaultEntry on OS versions < Win8.1. Use Get-PasswordVaultEntry instead"

    if ($PasswordVaultCompatibilityMode) {
        
        if ($PSCmdlet.ParameterSetName -like "UsernameAndResource") {
            Write-Warning "In compatibility mode, only one credential entry may be stored per target name"
            return Get-PVCMEntry @PSBoundParameters
        } else {
            throw "Finding credentials by username or resource only is not supported in this module on clients < Win8.1"
        }

    } else {
    
        $Vault = Get-PasswordVault

        try {
            if ($PSCmdlet.ParameterSetName -like "Username") {
                return $Vault.FindAllByUserName($Username)
            } elseif ($PSCmdlet.ParameterSetName -like "Resource") {
                return $Vault.FindAllByResource($Resource)
            } else {
                return ($Vault.FindAllByResource($Resource) | ?{$_.UserName -like $Username})
            }
            
        } catch [System.Management.Automation.MethodInvocationException] {
            if ($_ -like "*Element not found*") {Write-Debug "Entry was not present in Credential Manager"} else {throw $_}
        }

    }
}

function Get-PasswordVaultEntry {
    <#
        .SYNOPSIS
        Retrieves credentials from the Windows Password Vault or Credential Manager

        .DESCRIPTION
        Retrieves credentials from the Windows Password Vault or Credential Manager. You must run this command as the same user that stored the credential.

        If Username and Resource parameters are specified, only the credential matching those parameters will be returned. If no parameters are specified, all credentials will be returned, but without passwords.

        On Win8+, only Web Credentials are retrieved. On Win7, only generic credentials are retrieved. Credentials stored with Add-PasswordVaultEntry are always of these types, but credentials stored by the user in other ways may not be retrievable.

        On Win8+, this function wraps the Retrieve() method of Windows.Security.Credentials.PasswordVault. On Win7 and below, it wraps cmdkey to provide equivalent functionality.
        
        .PARAMETER Username
        The username of the credential

        .PARAMETER Resource
        The resource that the credential is for. For example, if the credential is for a web portal, this would be the URL.
        
        For CLI usage, the resource parameter can be considered a "Name" and can be anything. "Name" is an alias for this parameter.

        .PARAMETER AsPlaintext
        On Win7, makes the retrieved password visible. (On Win8+, the password is visible by default, so this switch has no effect.)

        .EXAMPLE
        Get-PasswordVaultEntry

        Returns all credentials of compatible type in the current user's Password Vault or Credential Manager. Passwords are omitted.

        .EXAMPLE
        Get-PasswordVaultEntry -Username "CONTOSO\bob" -Resource "PVScript#00034" -AsPlaintext

        Gets the credential with the resource identifier "PVScript#00034" and username "CONTOSO\bob". Password will be visible.
    #>

    [CmdletBinding(DefaultParameterSetName='NoParameters')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='ReturnDefault')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='ReturnPlaintext')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='ReturnPSCredential')]
        [Alias("Name")]
        [string]$Resource,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='ReturnDefault')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='ReturnPlaintext')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='ReturnPSCredential')]
        [string]$Username,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=2, ParameterSetName='ReturnPlaintext')]
        [switch]$AsPlaintext,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=2, ParameterSetName='ReturnPSCredential')]
        [switch]$AsPSCredential
    )


    if ($PasswordVaultCompatibilityMode) {
    
        $RawOutput = (Get-PVCMEntry @PSBoundParameters)

        if ($AsPSCredential) {
            return New-Object System.Management.Automation.PSCredential($RawOutput.Username, $RawOutput.Password)
        } else {
            return $RawOutput
        }

    } else {


        $Vault = Get-PasswordVault

        if ($PSCmdlet.ParameterSetName -like 'NoParameters') {
            return $Vault.RetrieveAll()

        } else {

            try {
                $RawOutput = $Vault.Retrieve($Resource, $Username)
            } catch [System.Management.Automation.MethodInvocationException] {
                if ($_ -like "*Element not found*") {Write-Debug "Entry $Resource, $Username was not present in Credential Manager"} else {throw $_}
            }


            if ($AsPSCredential) {
                return New-Object System.Management.Automation.PSCredential($RawOutput.Username, (ConvertTo-SecureString $RawOutput.Password -AsPlainText -Force))
            } else {
                return $RawOutput
            }


        }

    }
}


function ConvertTo-Plaintext {
    <#
        .SYNOPSIS
        Converts a SecureString to a plaintext string

        .DESCRIPTION
        Converts a SecureString to a plaintext string
        
        .PARAMETER SecureString
        The SecureString to convert to plaintext

        .EXAMPLE
        $Password = ConvertTo-SecureString "hunter2" -AsPlainText -Force
        ConvertTo-Plaintext -SecureString $Password

        Returns the plaintext string from a SecureString
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [Alias("SecurePassword")]
        [System.Security.SecureString]$SecureString
    )

    try {
        $UnsecurePointer = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        $UnsecureString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($UnsecurePointer)
    } finally {
        #This is important, it zeroes out the memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($UnsecurePointer)
    }

    return $UnsecureString
}




# don't export this!
function Get-PasswordVault {
    if (-not $Vault) {
        $Global:Vault = New-Object Windows.Security.Credentials.PasswordVault
    }
    return $Vault
}


#region private backward-compatibility functions; don't use these!

function Add-PVCMEntry {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)][string]$Username,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1)][string]$Password,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=2)][string]$Resource
    )


    function private:Stash {

        param($Password, $Chunk)
        $TargetName = $Resource + '_' + $Username
        if ($Chunk -is "int") {$TargetName = $TargetName + "_Chunk" + (([string]$Chunk).PadLeft(2, "0"))}
    
        $Result = cmdkey /generic:$TargetName /user:$Username /pass:$Password
        if ($Result -notlike "CMDKEY: Credential added successfully.") {throw $Result}

        #Write-host -ForegroundColor Cyan $($TargetName.padright(30) + $Password)
    }

    #Limit on secure data length per entry in Win 7 Credential Manager
    $MaxChunkSize = 1200
    
    
    if ($Password.Length -le $MaxChunkSize) { #cmdkey errors out if you try to store passwords > 1280 characters. It just hangs if the password > 2000 or so
        
        Stash $Password

    } else {
    
        $NumChunks = [Math]::Ceiling($Password.Length / $MaxChunkSize)

        for ($Chunk=0; $Chunk -lt $NumChunks; $Chunk++) {

            if ($Password.length -lt $MaxChunkSize) {
                Stash $Password $Chunk
                $Password = '' #defensive programming, should not calling after this
            } else {
                Stash ($Password.Substring(0, $MaxChunkSize)) $Chunk
                $Password = $Password.Substring($MaxChunkSize, $Password.Length-$MaxChunkSize)
            }

        }
    }


}

function Get-PVCMEntry {
    [CmdletBinding(DefaultParameterSetName='NoParameters')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='ReturnDefault')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='ReturnPlaintext')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0, ParameterSetName='ReturnPSCredential')]
        [Alias("Name")]
        [string]$Resource,

        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='ReturnDefault')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='ReturnPlaintext')]
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1, ParameterSetName='ReturnPSCredential')]
        [string]$Username,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=2, ParameterSetName='ReturnPlaintext')]
        [switch]$AsPlaintext,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=2, ParameterSetName='ReturnPSCredential')]
        [switch]$AsPSCredential
    )        
    
    if ($PSCmdlet.ParameterSetName -like 'NoParameters') {
        
        #list all results. Password will be Secure-String but will be EMPTY - don't bother to decode it. To get the password, rerun this function, specifying username and resource each time.

        $Results = @()
        $CmdKeyOutput = cmdkey /list
        if ($CmdKeyOutput.Count -lt 2) {return $null}
        for ($i=2; $i -lt $CmdKeyOutput.length; $i++) {
            
            $Result = New-Object psobject -Property @{Resource=$null; Type=$null; UserName=$null; Password=$null}
            
            for (; $CmdKeyOutput[$i] -notmatch '^\s*$'; $i++) {
                
                if ($CmdKeyOutput[$i] -like "*Local machine persistence*" -or $CmdKeyOutput[$i] -like "*Saved for this logon only*") {continue}
                
                $tokens = $CmdKeyOutput[$i].TrimStart().Split(' ',2)
                $Key = $tokens[0] -replace ':'
                $Value = $tokens[1].TrimEnd()
                
                if ($Key -like "Target") {
                    #PasswordVault refers to this property as "Resource", so we will call it that in compatibility mode too
                    $Key = "Resource"
                    $Value = ($Value.Split('=',2))[1]

                    #Obfuscate the fact that we sometimes have to split passwords into chunks - it is supposed to be transparent to the user
                    $Value = $Value -replace '_Chunk\d\d$'
                }
                if ($Key -like "User") {
                    #PasswordVault refers to this property as "UserName", so we will call it that in compatibility mode too
                    $Key = "UserName"
                    #We hacked the "Target" property to append "user"; this is to remove it again
                    $Result.Resource = $Result.Resource -replace [regex]::Escape('_' + $Value), ''
                }
                $Result.$Key = $Value
                
            }
            if ($Result.Type -like "Generic") {

                #Manipulate members to best preserve return types
                $Result.psobject.Members.Remove('Type')
                $Result.Password = New-Object securestring

                $Results += $Result
            }
        }

        return $Results | sort Resource, User, * -Unique


    } else {
    
        #get single result
        
        $TargetName = $Resource + '_' + $Username

        $Credential = Get-CMStoredCredential -Name $TargetName

        if ($Credential) {

            #Got it
            $Properties = @{Resource=$Resource; Username=$Credential.UserName}
            if ($AsPlaintext) {
                $Properties += @{Password=(ConvertTo-Plaintext -SecureString $Credential.Password)}
            } else {
                $Properties += @{Password=$Credential.Password}
            }
            return New-Object PSObject -Property $Properties

        } elseif (Get-CMStoredCredential -Name ($TargetName + "_Chunk00")) {
            
            #Didn't find it first time because it's there, but it was split into chunks when it was stored due to cmdkley limitation
            
            $PlaintextPassword = ''  #We must decrypt this, stitch it back together, and if required as secure-string, re-encrypt it.

            for ($Chunk=0; $true; $Chunk++) {

                $Credential = Get-CMStoredCredential -Name ($Resource + '_' + $Username + "_Chunk" + (([string]$Chunk).PadLeft(2, "0")))
                if (-not $Credential) {break}  #keep going until you run out of chunks. There may not be any.

                $PlaintextPassword += (ConvertTo-Plaintext -SecureString $Credential.Password)
                
            }

            $Properties = @{Resource=$Resource; Username=$UserName}
            if ($AsPlaintext) {
                $Properties += @{Password=$PlaintextPassword}
            } else {
                #Re-encrypt it now it has been stitched back together
                $Properties += @{Password=$(ConvertTo-SecureString $PlaintextPassword -AsPlainText -Force)}
            }

            return New-Object PSObject -Property $Properties


        } else {
            return $null
        }

    }
}

function Remove-PVCMEntry {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)][string]$Username,
        #[Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1)][string]$Password,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=1)][string]$Resource
    )

    $TargetName = $Resource + '_' + $Username
    $Result = cmdkey /delete:$TargetName

    if ($Result -like "CMDKEY: Element not found.") {
        $Chunk = 0
        do {
            $Result = cmdkey /delete:$($TargetName + "_Chunk" + (([string]$Chunk).PadLeft(2, "0")))
            $Chunk++

        } while ($Result -like "CMDKEY: Credential deleted successfully.")
    }

    if (-not ($Result -like "CMDKEY: Credential deleted successfully." -or $Result -like "CMDKEY: Element not found.")) {throw $Result}
}

function Find-PVCMEntry {
    Write-Warning "Find-PVCMEntry is deprecated. Use Get-PVCMEntry instead."
    return Get-PVCMEntry @PSBoundParameters
}

function Get-CMStoredCredential {
    <#
    .SYNOPSIS
    Gets a PowerShell Credential (PSCredential) from the Windows Credential Manager

    .DESCRIPTION
    This module will return a [PSCredential] object from a credential stored in Windows Credential Manager. The 
    Get-CMStoredCredential function can only access Generic Credentials.

    Alias: GSC

    .PARAMETER Name
    The name of the target login informations in the Windows Credential Manager

    .EXAMPLE
    PS C:\>Get-CMStoredCredential tfs.codeplex.com

    UserName                             Password
    --------                             --------
    codeplexuser                         System.Security.SecureString

    .EXAMPLE
    PS C:\>$cred = gsc production
    PS C:\>$conn = Connect-WSMan -ComputerName ProdServer -Credential $cred

    .INPUTS
    System.String

    .OUTPUTS
    System.Management.Automation.PSCredential

    .NOTES
    To add credentials open up Control Panel>User Accounts>Credential Manager and click "Add a gereric credential". 
    The "Internet or network address" field will be the Name required by the Get-StoredCredential function.

    https://gist.github.com/cdhunt/5729126

    Forked from https://gist.github.com/toburger/2947424 which was adapted from
    http://stackoverflow.com/questions/7162604/get-cached-credentials-in-powershell-from-windows-7-credential-manager

    .LINK
    Get-Credential

    .ROLE
    Operations

    .FUNCTIONALITY
    Security
    
    #>
    [OutputType([System.Management.Automation.PSCredential])]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("Address", "Location", "TargetName")]
        [string]$Name
    )

    End
    {
        $nCredPtr= New-Object IntPtr

        $success = [ADVAPI32.Util]::CredRead($Name,1,0,[ref] $nCredPtr)

        if ($success) {
            $critCred = New-Object ADVAPI32.Util+CriticalCredentialHandle $nCredPtr
            $cred = $critCred.GetCredential()
            $username = $cred.UserName
            $securePassword = $cred.CredentialBlob | ConvertTo-SecureString -AsPlainText -Force
            $critCred.Dispose()
            $critCred.Close()
            $cred = $null
            Write-Output (New-Object System.Management.Automation.PSCredential $username, $securePassword)
        } else {
            Write-Verbose "No credentials were found in Windows Credential Manager for TargetName: $Name"
        }
    }

    Begin
    {
        $sig = @"

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NativeCredential
{
    public UInt32 Flags;
    public CRED_TYPE Type;
    public IntPtr TargetName;
    public IntPtr Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize;
    public IntPtr CredentialBlob;
    public UInt32 Persist;
    public UInt32 AttributeCount;
    public IntPtr Attributes;
    public IntPtr TargetAlias;
    public IntPtr UserName;

    internal static NativeCredential GetNativeCredential(Credential cred)
    {
        NativeCredential ncred = new NativeCredential();
        ncred.AttributeCount = 0;
        ncred.Attributes = IntPtr.Zero;
        ncred.Comment = IntPtr.Zero;
        ncred.TargetAlias = IntPtr.Zero;
        ncred.Type = CRED_TYPE.GENERIC;
        ncred.Persist = (UInt32)1;
        ncred.CredentialBlobSize = (UInt32)cred.CredentialBlobSize;
        ncred.TargetName = Marshal.StringToCoTaskMemUni(cred.TargetName);
        ncred.CredentialBlob = Marshal.StringToCoTaskMemUni(cred.CredentialBlob);
        ncred.UserName = Marshal.StringToCoTaskMemUni(System.Environment.UserName);
        return ncred;
    }
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct Credential
{
    public UInt32 Flags;
    public CRED_TYPE Type;
    public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize;
    public string CredentialBlob;
    public UInt32 Persist;
    public UInt32 AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}

public enum CRED_TYPE : uint
    {
        GENERIC = 1,
        DOMAIN_PASSWORD = 2,
        DOMAIN_CERTIFICATE = 3,
        DOMAIN_VISIBLE_PASSWORD = 4,
        GENERIC_CERTIFICATE = 5,
        DOMAIN_EXTENDED = 6,
        MAXIMUM = 7,      // Maximum supported cred type
        MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
    }

public class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
{
    public CriticalCredentialHandle(IntPtr preexistingHandle)
    {
        SetHandle(preexistingHandle);
    }

    public Credential GetCredential()
    {
        if (!IsInvalid)
        {
            NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(handle,
                  typeof(NativeCredential));
            Credential cred = new Credential();
            cred.CredentialBlobSize = ncred.CredentialBlobSize;
            cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob,
                  (int)ncred.CredentialBlobSize / 2);
            cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
            cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
            cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
            cred.Type = ncred.Type;
            cred.Flags = ncred.Flags;
            cred.Persist = ncred.Persist;
            return cred;
        }
        else
        {
            throw new InvalidOperationException("Invalid CriticalHandle!");
        }
    }

    override protected bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            CredFree(handle);
            SetHandleAsInvalid();
            return true;
        }
        return false;
    }
}

[DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CredRead(string target, CRED_TYPE type, int reservedFlag, out IntPtr CredentialPtr);

[DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
public static extern bool CredFree([In] IntPtr cred);


"@
        try
        {
            Add-Type -MemberDefinition $sig -Namespace "ADVAPI32" -Name 'Util' -ErrorAction Stop
        }
        catch
        {
            Write-Error -Message "Could not load custom type. $($_.Exception.Message)"
        }
    
    }
}

#endregion



Export-ModuleMember -Function Add-PasswordVaultEntry, Remove-PasswordVaultEntry, Find-PasswordVaultEntry, Get-PasswordVaultEntry, ConvertTo-Plaintext
if ($Debug) {Export-ModuleMember *}