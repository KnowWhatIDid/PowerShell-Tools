<#
.SYNOPSIS
    Signs PowerShell scripts.
.DESCRIPTION
    Queries the user's personal certificate store to find the code-signing certificate.
    If $CertOwner is passed, it will look for a valid code signing certificate issued to 
    the cert owner.  Otherwise, it will look for a valid code signing certificate issued to
    the AD user executing the script.
.PARAMETER Path
    Mandatory [string] Path to the .ps1 file to be signed.
.PARAMETER CertOwner
    Optional [string] Entity to which the desired code signing certificate has been issued.
    If $CertOwner is not specified, the script will look for a valid code signing certificate
    issues to the AD user running the script.
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    VERSION 1.0.0
        Creation Date: 2019-11-08
        Author: John Trask
        Initial Release 
.EXAMPLE
    .\Sign-Script -Path C:\Scripts\New-Bananagram.ps1
.EXAMPLE
    .\Sign-Script -Path C:\Scripts\New-Bananagram.ps1 -CertOwner 'Hunt & Peck, Inc.'
#>

[CmdletBinding()]
Param (
    [Parameter(Position=0, Mandatory=$True)]
    [Alias("File")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$Path,

    [Parameter(Position=1, Mandatory=$False)]
    [string]$CertOwner
)

Function Sign-Script {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Path,

        [Parameter(Mandatory=$True)]
        [string]$CertOwner
    )

    Begin {
    }
    Process {
        If ($CertOwner -eq '') {
            $samAccountName = $env:USERNAME    
            $CertOwner = (Get-ADUser -Filter {samAccountName -eq $SamAccountName}).Name
        }
        $SearchFilter = "CN=$CertOwner*"
        
        $Cert = (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object {((Get-Date) -le $_.NotAfter) -and ((Get-Date) -ge $_.NotBefore) -and ($_.Subject -like $SearchFilter)})
        If ($Cert.Count -ne 1) {
            Write-Verbose "Found $($CertCount.Count) certificates."
            Write-Error "There was a problem retrieving the code signing certificate for $CertOwner"
        } Else {
            Write-Verbose "Signing $Path with $($Cert.Subject)"
            Set-AuthenticodeSignature $Path $Cert -TimestampServer http://time.certum.pl
        }
    }
    End {
        Write-Verbose "Process complete."
    }
}

Sign-Script -Path $Path -CertOwner:$CertOwner -Verbose:$VerbosePreference

