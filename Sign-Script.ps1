<#
.SYNOPSIS
    Signs PowerShell scripts.
.DESCRIPTION
    Queries the user's personal certificate store to find the code-signing certificate.

.INPUTS
    None
.OUTPUTS
    None
.NOTES
    VERSION 1.0.0
        Creation Date: 2019-11-07
        Author: John Trask
        Initial Release 
.EXAMPLE
    .\Sign-Script -Path C:\Scripts\New-Bananagram.ps1
.EXAMPLE
    .\Sign-Script -Path C:\Scripts\New-Bananagram.ps1 -External
#>

[CmdletBinding()]
Param (
    [Parameter(Position=0, Mandatory=$True)]
    [Alias("File")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$Path,

    [Parameter(Position=1, Mandatory=$False)]
    [switch]$External=$False
)

Function Sign-Script {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Path,

        [Parameter(Mandatory=$True)]
        [switch]$External
    )

    Begin {
    }
    Process {
        $samAccountName = $env:USERNAME    
        $UserName = (Get-ADUser -Filter {samAccountName -eq $SamAccountName}).Name
        If ($External) {
            $CertOwner = 'Hunt Consolidated, Inc.'
            $SearchFilter = "CN=`"$CertOwner*"
        } Else {
            $CertOwner = $UserName
            $SearchFilter = "CN=$UserName*"
        }

        $Cert = (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object {((Get-Date) -le $_.NotAfter) -and ((Get-Date) -ge $_.NotBefore) -and ($_.Subject -like $SearchFilter)})
        If ($Cert.Count -ne 1) {
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

Sign-Script -Path $Path -External:$External -Verbose:$VerbosePreference


# SIG # Begin signature block
# MIIQRgYJKoZIhvcNAQcCoIIQNzCCEDMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUROqG8r1d7F4juMHhJ2f0CAgo
# b32gggqfMIIE3DCCA8SgAwIBAgIRAP5n5PFaJOPGDVR8oCDCdnAwDQYJKoZIhvcN
# AQELBQAwfjELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9n
# aWVzIFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
# eTEiMCAGA1UEAxMZQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQTAeFw0xNjAzMDgx
# MzEwNDNaFw0yNzA1MzAxMzEwNDNaMHcxCzAJBgNVBAYTAlBMMSIwIAYDVQQKDBlV
# bml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLDB5DZXJ0dW0gQ2VydGlm
# aWNhdGlvbiBBdXRob3JpdHkxGzAZBgNVBAMMEkNlcnR1bSBFViBUU0EgU0hBMjCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9Xi7yRM1ouVzF/JVf0W1NY
# aiWq6IEgzA0dRzhwGqMWN523RHS1GoEk+vUYSjhLC6C6xb80b+qM9Z1CGtAxqFbd
# qCUOtDwlxazGy1zjgJLqo68tAEBAfNJBKB8rCOhR0F2JcCJsaXbQdhI8LksHKSbp
# +AHh0OUo9iTDFfqmkIR0hVyDLA7E2nhJlGodJIaX6SLAxgw14HQyqj27Adh+zBNM
# IMeVLUn28S0XvMYp9/hVdpx9Fdze4UKVk2CZ90PFlEIhvZisHLNm3P14YEQ/PcSV
# aWfuYcva0LnmdvehPwT00+dxryECXhHaU6SmtZF42ZARW7Sh7qduCtlzpDgFUiMC
# AwEAAaOCAVowggFWMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPM1yo5GCA05jd9B
# xzNuZOQWO5grMB8GA1UdIwQYMBaAFAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1Ud
# DwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAvBgNVHR8EKDAmMCSg
# IqAghh5odHRwOi8vY3JsLmNlcnR1bS5wbC9jdG5jYS5jcmwwawYIKwYBBQUHAQEE
# XzBdMCgGCCsGAQUFBzABhhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDEG
# CCsGAQUFBzAChiVodHRwOi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EuY2Vy
# MEAGA1UdIAQ5MDcwNQYLKoRoAYb2dwIFAQswJjAkBggrBgEFBQcCARYYaHR0cDov
# L3d3dy5jZXJ0dW0ucGwvQ1BTMA0GCSqGSIb3DQEBCwUAA4IBAQDKdOQ4vTLJGjz6
# K1jFVy01UwuQ3i0FsvEzMkAblv8iRYc5rgzwGc7B0DJEGjMMgOs9Myt8eTROxoFE
# NFhWujkN8OSzA6w3dcB667dA9pr8foBtqbRViT2YSMpW9FWkLunh0361OJGVxM+7
# ph51a1ZQm26n69Gc4XEg1dWmWKvh5SldgfEEteQbZEKhOHE9e3NkxmnUIjCWsCTD
# AlsRqDw0YntnZ+FGhld86IqfkLs4W9m1ieoDKNuNt1sHbTK7h3/cJs4uXujWq9vm
# ptDiGQIS+aDbPp1SxEy9V4XteO3BlkTNRrDOZdVXcjokxhDhsHPEj1qDrPbGcpT5
# cnf/AdUhMIIFuzCCBKOgAwIBAgITcAAABg6O/4CtL6GG7wAAAAAGDjANBgkqhkiG
# 9w0BAQsFADBGMRMwEQYKCZImiZPyLGQBGRYDcHZ0MRMwEQYKCZImiZPyLGQBGRYD
# SENJMRowGAYDVQQDExFIQ0ktSENJREFMQVMyMC1DQTAeFw0xOTA4MzAxMzMwNTRa
# Fw0yMDA4MjkxMzMwNTRaMFUxEzARBgoJkiaJk/IsZAEZFgNwdnQxEzARBgoJkiaJ
# k/IsZAEZFgNIQ0kxDjAMBgNVBAMTBVVzZXJzMRkwFwYDVQQDExBKb2huIFRyYXNr
# IChBRE0pMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuA4zz3wwd9aB
# +53i3BXGcxdrhs1yE4FcxNCt79UwAvXumsupP3LkF/fsMR7lViUva0vAoKs1FCik
# lqyVU/6aWercOe2p2fYz6fgr0MbyaMqGjZUVSYh+Y7QWbAC+q6UhqulCqWQa9TK7
# +bLui5Obm4NmtEpP9Hgub51t1LW3LS+S53oHpDU9k3xz0S5WRlfbuwKJwjEWPkGV
# qGDg4WkvlqZEjj2JE+pxLm38M+FAqg/GIkpMe4PVPCoHU96gu/b1kp8XbTgCU+6E
# ppEpcOdnR80ecbbIHR6P5VZJOQFkO1wTEOBmLCSVzK73R/611OVFDlN+PrfhIyRS
# LxyZriuZYQIDAQABo4ICkTCCAo0wPgYJKwYBBAGCNxUHBDEwLwYnKwYBBAGCNxUI
# gcSJeYOargSHiZELgffddYKvsV+BIoSNmTeBs5N5AgFkAgEDMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMAsGA1UdDwQEAwIHgDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUF
# BwMDMB0GA1UdDgQWBBTgTGTsVhUyNqtUg0pqtEnoT7A9UTAfBgNVHSMEGDAWgBTB
# HozxIEZuAzEtw1FDxiF/lDX9WjCBzgYDVR0fBIHGMIHDMIHAoIG9oIG6hoG3bGRh
# cDovLy9DTj1IQ0ktSENJREFMQVMyMC1DQSxDTj1IQ0lEQUxBUzIwLENOPUNEUCxD
# Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
# cmF0aW9uLERDPUhDSSxEQz1wdnQ/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9i
# YXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIG/BggrBgEFBQcB
# AQSBsjCBrzCBrAYIKwYBBQUHMAKGgZ9sZGFwOi8vL0NOPUhDSS1IQ0lEQUxBUzIw
# LUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
# cyxDTj1Db25maWd1cmF0aW9uLERDPUhDSSxEQz1wdnQ/Y0FDZXJ0aWZpY2F0ZT9i
# YXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwOQYDVR0RBDIw
# MKAuBgorBgEEAYI3FAIDoCAMHmFkbWp0cmFza0BodW50Y29uc29saWRhdGVkLmNv
# bTANBgkqhkiG9w0BAQsFAAOCAQEAazmWjRXQBUd9SHrX2ELc2XROxsjq0Bp+uAvp
# W1tGXJ6roHEosVN29q1RB8kRJxJX2yOBRzbhbmS74RiJK4hlsLbKk7Q2gXrlUjR+
# xbpJ2+aUO7KNduJUJJt9rlAEWr1Jkt+C/ksA25tMLMI02730xan+ylz5As1ldw29
# VMCA5PRk5Mq6AXRk39WgXV8/S2A1NXS0MPih+iwhUrCbPusQGBVWTIXd34Hqu46R
# oBOzaOXN4A+S0b9s2nmTeOHCbPB1BS3xKlYBTAOUknLQ+b0/3OlVGBk/ILzxLZ9E
# 4Jp/SZ1cJpLj6N/q8G7RTPrh+sFAM2C9RMXDvdet4DEp//g5gTGCBREwggUNAgEB
# MF0wRjETMBEGCgmSJomT8ixkARkWA3B2dDETMBEGCgmSJomT8ixkARkWA0hDSTEa
# MBgGA1UEAxMRSENJLUhDSURBTEFTMjAtQ0ECE3AAAAYOjv+ArS+hhu8AAAAABg4w
# CQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcN
# AQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUw
# IwYJKoZIhvcNAQkEMRYEFLjxGFuxX2LERpzGWSxXJSdCdkDtMA0GCSqGSIb3DQEB
# AQUABIIBACty3obyArIPyXAD2mNN8TRoCX7tC/1dZaiCsA27D8oO8fAD9p7NojTi
# /UyqBInLDBqS8izeTM4K1YUVCNq2aIGlg/DxOpAJvUS/97hjX8NfrG1w9msWzTL2
# cVh2LdmCv2OyDTS7xcf5JiZ7fwXi3gv4EWQoybmKwYP2Ua4XIJoXH/WtuA2vA83U
# z9LW246kLHZ9QNck5J18+/PCLRkdQQxXXtaC3D+JRJJAkdQsFM6oFSD+bP3inKeH
# EgCZu74W0+w9+xwbEj4/8b8gZe2JLqAJDcZAFYXBMYJCU8jkXLO5LnezbLt02gdj
# mw/w8CsdDQaiKQnOweBjL5+cyhDRtMmhggMPMIIDCwYJKoZIhvcNAQkGMYIC/DCC
# AvgCAQEwgZMwfjELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5v
# bG9naWVzIFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhv
# cml0eTEiMCAGA1UEAxMZQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQQIRAP5n5PFa
# JOPGDVR8oCDCdnAwDQYJYIZIAWUDBAIBBQCgggE5MBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMTkwOTA0MTkwMDE1WjAvBgkqhkiG
# 9w0BCQQxIgQgyHuaRyqNmixI/fpjLIX77gCqwOKYTMIdQ9xJV1504SIwgcsGCyqG
# SIb3DQEJEAIMMYG7MIG4MIG1MIGyBBRPjUxIBklCau+LhtTV/Hky5xQthTCBmTCB
# g6SBgDB+MQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSIwIAYDVQQDExlDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBAhEA/mfk8Vok48YN
# VHygIMJ2cDANBgkqhkiG9w0BAQEFAASCAQCdEMfbbQAR3sJWqLl8oTa8NGYwO+9P
# X97CRK6N+mt+bNn48e/tvthy11NzH9fqY26ZKu+BmssifLEnMZ6u0SANQE0880rw
# YMFl7kPcDkT9TZS+79MUycms3jBxAsg1Zixd2gRH/P9zfYXS7AX2T+2rOHgPThv7
# jGux8e+zrnoUUsMQMnMQK8lhXEAvdsOui5BhSdwiexXdeqgZ+GzDS72UxGFzn3ax
# qpCwPVDXy594Zu5FfsVwewY0/1gILGafhE/5Xz+5IcJeZX40KVTIIitR7GYiiwi4
# 8n5Yo2DeLA8aN3oRU8pZi1JmDPf2icCWZK+aOa42/Q9s/glmq00uKg5Y
# SIG # End signature block
