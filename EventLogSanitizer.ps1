<#
.SYNOPSIS
    Windows Event Log Sanitizer - Offline EVTX Files

.DESCRIPTION
    Reads downloaded .EVTX files from a specified folder and creates
    an independent sanitized CSV and JSON file for EACH EVTX file.

    Output filename format:

        TYYYYMMDD.####_YYYYMMDDTHHMMSS-####_LogName_Sanitized.csv
        TYYYYMMDD.####_YYYYMMDDTHHMMSS-####_LogName_Sanitized.json

    Example:

        T20260922.0001_20260922T160356-0500_Application_Sanitized.csv
        T20260922.0001_20260922T160356-0500_Application_Sanitized.json

    The timestamp uses the LOCAL time of the computer running this
    script and includes its UTC offset.

    The script:

      - Reads ONLY downloaded EVTX files.
      - Does NOT read the computer's live Windows Event Logs.
      - Does NOT modify, move, copy, or delete the source EVTX files.
      - Does NOT combine different EVTX files.
      - Creates one CSV and one JSON per EVTX file.
      - Uses the EVTX's internal Windows log/channel name in the
        output filename rather than the source filename.
      - Processes sensitive values in memory.
      - Uses one-way pseudonyms for identifying information.
      - Redacts common credential/token patterns.
      - Allows optional customer-specific sensitive terms.

.SECURITY
    Automated sanitization cannot guarantee removal of all PHI, PII,
    customer names, patient names, case names, filenames, or arbitrary
    sensitive information contained in free-form event messages.

    Manually review sanitized files before uploading data from regulated
    or highly confidential environments.

.EXAMPLE
    .\EventLogSanitizer.ps1 `
        -FolderPath "C:\Temp\EventLogs" `
        -TicketNumber "T20260922.0001"

.EXAMPLE
    .\EventLogSanitizer.ps1 `
        -FolderPath "C:\Temp\EventLogs" `
        -TicketNumber "T20260922.0001" `
        -SensitiveTerms @(
            "Contoso Medical",
            "contoso.local",
            "contoso.com",
            "John Smith"
        )

.NOTES
    Intended for Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param (

    # --------------------------------------------------------
    # Folder containing the downloaded EVTX files.
    # --------------------------------------------------------

    [Parameter(
        Mandatory = $true,
        Position = 0
    )]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Container)) {
            throw "Folder does not exist: $_"
        }

        $true
    })]
    [string]$FolderPath,


    # --------------------------------------------------------
    # PSA ticket number.
    #
    # Required format:
    #
    # TYYYYMMDD.####
    #
    # Example:
    #
    # T20260922.0001
    # --------------------------------------------------------

    [Parameter(
        Mandatory = $true
    )]
    [ValidatePattern('^T\d{8}\.\d{4}$')]
    [string]$TicketNumber,


    # --------------------------------------------------------
    # Optional known-sensitive values.
    #
    # Examples:
    #
    # Customer names
    # Domains
    # Usernames
    # Server names
    # Patient/client names
    # Matter/case names
    # --------------------------------------------------------

    [Parameter()]
    [string[]]$SensitiveTerms = @()
)


Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


# ============================================================
# RESOLVE SOURCE FOLDER
# ============================================================

$FolderPath = (
    Resolve-Path -LiteralPath $FolderPath
).Path


# ============================================================
# FIND DOWNLOADED EVTX FILES
#
# Only EVTX files directly inside the supplied folder are
# processed. Subdirectories are not searched.
# ============================================================

$EvtxFiles = @(
    Get-ChildItem `
        -LiteralPath $FolderPath `
        -Filter '*.evtx' `
        -File `
        -ErrorAction Stop |
    Sort-Object Name
)


if ($EvtxFiles.Count -eq 0) {

    throw "No .evtx files were found in: $FolderPath"
}


# ============================================================
# CREATE ONE LOCAL TIMESTAMP FOR THIS ENTIRE RUN
#
# ISO 8601 basic/compact format with UTC offset:
#
# YYYYMMDDTHHMMSS-HHMM
#
# Example during Central Daylight Time:
#
# 20260922T160356-0500
#
# Example during Central Standard Time:
#
# 20261222T160356-0600
#
# DateTimeOffset is used so the current local UTC offset is
# preserved.
#
# "zzz" normally produces "-05:00". The colon is removed
# because ":" is not valid in Windows filenames.
# ============================================================

$LocalTimestamp = (
    [DateTimeOffset]::Now.ToString(
        "yyyyMMdd'T'HHmmsszzz"
    )
).Replace(':', '')


# ============================================================
# RANDOM PER-RUN SALT
#
# Used to generate one-way pseudonyms.
#
# The salt is never written to disk.
#
# The same original value receives the same pseudonym throughout
# this run, including across multiple EVTX files.
#
# A future sanitization run will generate different pseudonyms.
# ============================================================

$script:Salt = New-Object byte[] 32

$Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

try {

    $Rng.GetBytes($script:Salt)

}
finally {

    $Rng.Dispose()
}


# ============================================================
# PREPARE USER-SUPPLIED SENSITIVE TERMS
# ============================================================

$script:BaseSensitiveTerms = @(
    $SensitiveTerms |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } |
    ForEach-Object {
        $_.Trim()
    } |
    Sort-Object Length -Descending -Unique
)


# ============================================================
# CREATE ONE-WAY PSEUDONYM
# ============================================================

function Get-Pseudonym {

    param (

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Prefix,

        [Parameter(Mandatory)]
        [string]$Value
    )


    if ([string]::IsNullOrWhiteSpace($Value)) {

        return $Value
    }


    $InputBytes = [System.Text.Encoding]::UTF8.GetBytes(
        "$Category|$Value"
    )


    $CombinedBytes = New-Object byte[] (
        $script:Salt.Length + $InputBytes.Length
    )


    [Array]::Copy(
        $script:Salt,
        0,
        $CombinedBytes,
        0,
        $script:Salt.Length
    )


    [Array]::Copy(
        $InputBytes,
        0,
        $CombinedBytes,
        $script:Salt.Length,
        $InputBytes.Length
    )


    $Sha = [System.Security.Cryptography.SHA256]::Create()

    try {

        $Hash = $Sha.ComputeHash($CombinedBytes)

    }
    finally {

        $Sha.Dispose()
    }


    $ShortHash = (
        [BitConverter]::ToString(
            $Hash,
            0,
            5
        )
    ).Replace('-', '')


    return "[$Prefix-$ShortHash]"
}


# ============================================================
# TOKENIZE REGEX MATCHES
# ============================================================

function Replace-TokenizedPattern {

    param (

        [AllowNull()]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [string]$Prefix
    )


    if ([string]::IsNullOrEmpty($Text)) {

        return $Text
    }


    return [regex]::Replace(
        $Text,
        $Pattern,
        {
            param($Match)

            Get-Pseudonym `
                -Category $Category `
                -Prefix $Prefix `
                -Value $Match.Value
        },
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
}


# ============================================================
# REDACT SECRET PATTERNS
# ============================================================

function Replace-SecretPattern {

    param (

        [AllowNull()]
        [string]$Text,

        [Parameter(Mandatory)]
        [string]$Pattern,

        [Parameter(Mandatory)]
        [string]$Replacement
    )


    if ([string]::IsNullOrEmpty($Text)) {

        return $Text
    }


    return [regex]::Replace(
        $Text,
        $Pattern,
        $Replacement,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
}


# ============================================================
# IPv4 SANITIZATION
# ============================================================

function Protect-IPv4Addresses {

    param (

        [AllowNull()]
        [string]$Text
    )


    if ([string]::IsNullOrEmpty($Text)) {

        return $Text
    }


    $Pattern = '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'


    return [regex]::Replace(
        $Text,
        $Pattern,
        {

            param($Match)


            $IPAddress = $null


            if (
                -not [System.Net.IPAddress]::TryParse(
                    $Match.Value,
                    [ref]$IPAddress
                )
            ) {

                return $Match.Value
            }


            if (
                $IPAddress.AddressFamily -ne
                [System.Net.Sockets.AddressFamily]::InterNetwork
            ) {

                return $Match.Value
            }


            # Common non-identifying addresses are retained.

            if (
                $Match.Value -eq '0.0.0.0' -or
                $Match.Value -eq '127.0.0.1' -or
                $Match.Value -eq '255.255.255.255'
            ) {

                return $Match.Value
            }


            $Bytes = $IPAddress.GetAddressBytes()

            $Prefix = 'PUBLIC-IP'


            # RFC1918: 10.0.0.0/8

            if ($Bytes[0] -eq 10) {

                $Prefix = 'PRIVATE-IP'
            }


            # RFC1918: 172.16.0.0/12

            elseif (
                $Bytes[0] -eq 172 -and
                $Bytes[1] -ge 16 -and
                $Bytes[1] -le 31
            ) {

                $Prefix = 'PRIVATE-IP'
            }


            # RFC1918: 192.168.0.0/16

            elseif (
                $Bytes[0] -eq 192 -and
                $Bytes[1] -eq 168
            ) {

                $Prefix = 'PRIVATE-IP'
            }


            # Link-local / APIPA

            elseif (
                $Bytes[0] -eq 169 -and
                $Bytes[1] -eq 254
            ) {

                $Prefix = 'LINKLOCAL-IP'
            }


            return Get-Pseudonym `
                -Category 'IPv4' `
                -Prefix $Prefix `
                -Value $Match.Value
        }
    )
}


# ============================================================
# IPv6 SANITIZATION
# ============================================================

function Protect-IPv6Addresses {

    param (

        [AllowNull()]
        [string]$Text
    )


    if ([string]::IsNullOrEmpty($Text)) {

        return $Text
    }


    $Pattern =
        '(?<![0-9A-Fa-f:])' +
        '(?=[0-9A-Fa-f:]*:)' +
        '[0-9A-Fa-f:]{2,}' +
        '(?![0-9A-Fa-f:])'


    return [regex]::Replace(
        $Text,
        $Pattern,
        {

            param($Match)


            $IPAddress = $null


            if (
                -not [System.Net.IPAddress]::TryParse(
                    $Match.Value,
                    [ref]$IPAddress
                )
            ) {

                return $Match.Value
            }


            if (
                $IPAddress.AddressFamily -ne
                [System.Net.Sockets.AddressFamily]::InterNetworkV6
            ) {

                return $Match.Value
            }


            # IPv6 loopback is not identifying.

            if (
                $IPAddress.Equals(
                    [System.Net.IPAddress]::IPv6Loopback
                )
            ) {

                return $Match.Value
            }


            return Get-Pseudonym `
                -Category 'IPv6' `
                -Prefix 'IPV6' `
                -Value $Match.Value
        }
    )
}


# ============================================================
# CUSTOMER-SPECIFIC TERMS
# ============================================================

function Protect-SensitiveTerms {

    param (

        [AllowNull()]
        [string]$Text
    )


    if ([string]::IsNullOrEmpty($Text)) {

        return $Text
    }


    foreach ($Term in $script:CurrentSensitiveTerms) {

        if ([string]::IsNullOrWhiteSpace($Term)) {

            continue
        }


        $Pattern = [regex]::Escape($Term)


        $Text = [regex]::Replace(
            $Text,
            $Pattern,
            {

                param($Match)


                Get-Pseudonym `
                    -Category 'SensitiveTerm' `
                    -Prefix 'CUSTOM' `
                    -Value $Match.Value
            },
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }


    return $Text
}


# ============================================================
# MAIN TEXT SANITIZER
# ============================================================

function Protect-EventText {

    param (

        [AllowNull()]
        [string]$Text
    )


    if ([string]::IsNullOrEmpty($Text)) {

        return $Text
    }


    # --------------------------------------------------------
    # AUTHORIZATION BEARER TOKENS
    # --------------------------------------------------------

    $Text = Replace-SecretPattern `
        -Text $Text `
        -Pattern '\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*' `
        -Replacement 'Authorization: Bearer [REDACTED-SECRET]'


    # --------------------------------------------------------
    # PASSWORD / SECRET / API KEY FIELDS
    # --------------------------------------------------------

    $Text = Replace-SecretPattern `
        -Text $Text `
        -Pattern '\b(password|passwd|pwd|passphrase|client_secret|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token)\b\s*[:=]\s*[^\s;,&]+' `
        -Replacement '$1=[REDACTED-SECRET]'


    # --------------------------------------------------------
    # JWT TOKENS
    # --------------------------------------------------------

    $Text = Replace-SecretPattern `
        -Text $Text `
        -Pattern '\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b' `
        -Replacement '[REDACTED-JWT]'


    # --------------------------------------------------------
    # AWS ACCESS KEYS
    # --------------------------------------------------------

    $Text = Replace-SecretPattern `
        -Text $Text `
        -Pattern '\bAKIA[0-9A-Z]{16}\b' `
        -Replacement '[REDACTED-AWS-KEY]'


    # --------------------------------------------------------
    # GITHUB TOKENS
    # --------------------------------------------------------

    $Text = Replace-SecretPattern `
        -Text $Text `
        -Pattern '\bgh[pousr]_[A-Za-z0-9]{20,}\b' `
        -Replacement '[REDACTED-GITHUB-TOKEN]'


    # --------------------------------------------------------
    # URLs
    #
    # Entire URL is pseudonymized because the path and query
    # string can contain identifying or authentication data.
    # --------------------------------------------------------

    $Text = Replace-TokenizedPattern `
        -Text $Text `
        -Pattern '\b(?:https?|ftp)://[^\s<>"'']+' `
        -Category 'URL' `
        -Prefix 'URL'


    # --------------------------------------------------------
    # UNC PATHS
    # --------------------------------------------------------

    $Text = Replace-TokenizedPattern `
        -Text $Text `
        -Pattern '\\\\[A-Za-z0-9._$-]+\\[^\s<>"'']+' `
        -Category 'UNCPath' `
        -Prefix 'UNC'


    # --------------------------------------------------------
    # EMAIL ADDRESSES
    # --------------------------------------------------------

    $Text = Replace-TokenizedPattern `
        -Text $Text `
        -Pattern '\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b' `
        -Category 'Email' `
        -Prefix 'EMAIL'


    # --------------------------------------------------------
    # WINDOWS USER PROFILE PATHS
    #
    # Example:
    #
    # C:\Users\JohnSmith\AppData
    #
    # becomes:
    #
    # C:\Users\[PROFILE-XXXXXXXXXX]\AppData
    # --------------------------------------------------------

    $Text = [regex]::Replace(
        $Text,
        '(?i)(\b[A-Z]:\\Users\\)([^\\\s<>"'']+)',
        {

            param($Match)


            $PathPrefix = $Match.Groups[1].Value

            $Profile = $Match.Groups[2].Value


            $Token = Get-Pseudonym `
                -Category 'UserProfile' `
                -Prefix 'PROFILE' `
                -Value $Profile


            return "$PathPrefix$Token"
        }
    )


    # --------------------------------------------------------
    # DOMAIN\USERNAME
    # --------------------------------------------------------

    $Text = [regex]::Replace(
        $Text,
        '(?i)(?<![A-Z0-9_.-])[A-Z0-9._$-]{1,64}\\[A-Z0-9._@$+-]{1,128}(?![A-Z0-9_.-])',
        {

            param($Match)


            return Get-Pseudonym `
                -Category 'Account' `
                -Prefix 'ACCOUNT' `
                -Value $Match.Value
        }
    )


    # --------------------------------------------------------
    # WINDOWS SECURITY IDENTIFIERS
    # --------------------------------------------------------

    $Text = [regex]::Replace(
        $Text,
        '\bS-\d-(?:\d+-){1,14}\d+\b',
        {

            param($Match)


            # Well-known service identities are retained.

            if (
                $Match.Value -eq 'S-1-5-18' -or
                $Match.Value -eq 'S-1-5-19' -or
                $Match.Value -eq 'S-1-5-20'
            ) {

                return $Match.Value
            }


            return Get-Pseudonym `
                -Category 'SID' `
                -Prefix 'SID' `
                -Value $Match.Value
        },
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )


    # --------------------------------------------------------
    # MAC ADDRESSES
    # --------------------------------------------------------

    $Text = Replace-TokenizedPattern `
        -Text $Text `
        -Pattern '\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b' `
        -Category 'MAC' `
        -Prefix 'MAC'


    # --------------------------------------------------------
    # IP ADDRESSES
    # --------------------------------------------------------

    $Text = Protect-IPv4Addresses `
        -Text $Text


    $Text = Protect-IPv6Addresses `
        -Text $Text


    # --------------------------------------------------------
    # CUSTOMER-SPECIFIC TERMS
    # --------------------------------------------------------

    $Text = Protect-SensitiveTerms `
        -Text $Text


    return $Text
}


# ============================================================
# MAKE WINDOWS EVENT LOG NAME SAFE FOR USE IN A FILENAME
# ============================================================

function Get-SafeLogFileName {

    param (

        [Parameter(Mandatory)]
        [string]$LogName
    )


    $SafeName = $LogName


    # Windows-invalid filename characters.

    $SafeName = $SafeName -replace '[<>:"/\\|?*]', '_'


    # Replace whitespace with underscores.

    $SafeName = $SafeName -replace '\s+', '_'


    # Collapse repeated underscores.

    $SafeName = $SafeName -replace '_+', '_'


    # Remove potentially problematic leading/trailing characters.

    $SafeName = $SafeName.Trim('.', '_', ' ')


    if ([string]::IsNullOrWhiteSpace($SafeName)) {

        return 'UnknownEventLog'
    }


    return $SafeName
}


# ============================================================
# START
# ============================================================

Write-Host ""
Write-Host "=============================================="
Write-Host "Windows Event Log Sanitizer"
Write-Host "=============================================="
Write-Host ""
Write-Host "Ticket:"
Write-Host "  $TicketNumber"
Write-Host ""
Write-Host "Source folder:"
Write-Host "  $FolderPath"
Write-Host ""
Write-Host "Local run timestamp:"
Write-Host "  $LocalTimestamp"
Write-Host ""
Write-Host "EVTX files found:"
Write-Host "  $($EvtxFiles.Count)"
Write-Host ""


$SuccessfulFiles = 0
$FailedFiles = 0
$TotalEvents = 0


# ============================================================
# PROCESS EACH EVTX INDEPENDENTLY
# ============================================================

foreach ($EvtxFile in $EvtxFiles) {

    Write-Host "----------------------------------------------"
    Write-Host "Processing:"
    Write-Host "  $($EvtxFile.Name)"


    # Reset sensitive terms for this file.

    $script:CurrentSensitiveTerms = @(
        $script:BaseSensitiveTerms
    )


    # --------------------------------------------------------
    # READ THIS EVTX FILE
    # --------------------------------------------------------

    try {

        $Events = @(
            Get-WinEvent `
                -Path $EvtxFile.FullName `
                -ErrorAction Stop
        )

    }
    catch {

        $FailedFiles++

        Write-Warning (
            "Could not read EVTX file: $($EvtxFile.Name)"
        )

        Write-Warning $_.Exception.Message

        continue
    }


    if ($Events.Count -eq 0) {

        $FailedFiles++

        Write-Warning (
            "No events were found in $($EvtxFile.Name)"
        )

        continue
    }


    Write-Host "Events found:"
    Write-Host "  $($Events.Count)"


    # --------------------------------------------------------
    # DETERMINE INTERNAL WINDOWS EVENT LOG / CHANNEL NAME
    #
    # We intentionally do NOT use the original filename in
    # the sanitized output filename. The downloaded filename
    # could itself contain customer-identifying information.
    # --------------------------------------------------------

    $InternalLogName = (
        $Events |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [string]$_.LogName
            )
        } |
        Select-Object `
            -First 1 `
            -ExpandProperty LogName
    )


    if ([string]::IsNullOrWhiteSpace($InternalLogName)) {

        $InternalLogName = 'UnknownEventLog'
    }


    $SafeLogName = Get-SafeLogFileName `
        -LogName $InternalLogName


    # --------------------------------------------------------
    # OUTPUT FILENAMES
    #
    # Format:
    #
    # Ticket_LocalTimestamp_LogName_Sanitized.ext
    # --------------------------------------------------------

    $OutputBaseName = (
        '{0}_{1}_{2}_Sanitized' -f
        $TicketNumber,
        $LocalTimestamp,
        $SafeLogName
    )


    $CsvPath = Join-Path `
        $FolderPath `
        "$OutputBaseName.csv"


    $JsonPath = Join-Path `
        $FolderPath `
        "$OutputBaseName.json"


    # --------------------------------------------------------
    # DISCOVER MACHINE NAMES FIRST
    #
    # This allows computer names to be removed if they also
    # appear inside Message or EventData fields.
    # --------------------------------------------------------

    $MachineNames = @(
        $Events |
        ForEach-Object {
            [string]$_.MachineName
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        } |
        Sort-Object -Unique
    )


    foreach ($MachineName in $MachineNames) {

        $script:CurrentSensitiveTerms += $MachineName
    }


    $script:CurrentSensitiveTerms = @(
        $script:CurrentSensitiveTerms |
        Sort-Object Length -Descending -Unique
    )


    # --------------------------------------------------------
    # SANITIZE EVENTS
    # --------------------------------------------------------

    $Results = New-Object `
        'System.Collections.Generic.List[object]'


    foreach ($Event in $Events) {


        # ----------------------------------------------------
        # EVENT TIMESTAMP
        #
        # This remains the timestamp contained in the original
        # Event Log record. It is not replaced with the script
        # execution time.
        # ----------------------------------------------------

        $SafeTimeCreated = ''


        if ($null -ne $Event.TimeCreated) {

            $SafeTimeCreated =
                $Event.TimeCreated.ToString('o')
        }


        # ----------------------------------------------------
        # MACHINE NAME
        # ----------------------------------------------------

        $SafeMachineName = ''


        if (
            -not [string]::IsNullOrWhiteSpace(
                [string]$Event.MachineName
            )
        ) {

            $SafeMachineName = Get-Pseudonym `
                -Category 'Host' `
                -Prefix 'HOST' `
                -Value ([string]$Event.MachineName)
        }


        # ----------------------------------------------------
        # USER SID
        # ----------------------------------------------------

        $SafeUserId = ''


        if ($null -ne $Event.UserId) {

            $RawUserId = [string]$Event.UserId


            if (
                $RawUserId -eq 'S-1-5-18' -or
                $RawUserId -eq 'S-1-5-19' -or
                $RawUserId -eq 'S-1-5-20'
            ) {

                $SafeUserId = $RawUserId

            }
            else {

                $SafeUserId = Get-Pseudonym `
                    -Category 'SID' `
                    -Prefix 'SID' `
                    -Value $RawUserId
            }
        }


        # ----------------------------------------------------
        # EVENT MESSAGE
        # ----------------------------------------------------

        try {

            $RawMessage = [string]$Event.Message

        }
        catch {

            $RawMessage = ''
        }


        if ([string]::IsNullOrWhiteSpace($RawMessage)) {

            $RawMessage =
                '[MESSAGE TEXT UNAVAILABLE - SEE EVENTDATA]'
        }


        $SafeMessage = Protect-EventText `
            -Text $RawMessage


        # ----------------------------------------------------
        # EVENT PROPERTY DATA
        #
        # Event.Properties can remain useful when the system
        # analyzing the downloaded EVTX does not have the
        # original event provider's message resource files.
        # ----------------------------------------------------

        $PropertyValues = @()


        if ($null -ne $Event.Properties) {

            foreach ($Property in $Event.Properties) {

                if ($null -eq $Property.Value) {

                    $PropertyValues += ''

                }
                elseif ($Property.Value -is [byte[]]) {

                    # Avoid exporting arbitrary binary payloads.

                    $PropertyValues += '[BINARY-DATA]'

                }
                else {

                    $PropertyValues +=
                        [string]$Property.Value
                }
            }
        }


        $RawEventData = $PropertyValues -join ' | '


        $SafeEventData = Protect-EventText `
            -Text $RawEventData


        # ----------------------------------------------------
        # KEYWORDS
        # ----------------------------------------------------

        $RawKeywords = ''


        if ($null -ne $Event.KeywordsDisplayNames) {

            $RawKeywords =
                $Event.KeywordsDisplayNames -join '; '
        }


        $SafeKeywords = Protect-EventText `
            -Text $RawKeywords


        # ----------------------------------------------------
        # CREATE SANITIZED OUTPUT RECORD
        # ----------------------------------------------------

        $Record = [pscustomobject][ordered]@{

            LogName = Protect-EventText `
                -Text ([string]$Event.LogName)

            TimeCreated = $SafeTimeCreated

            RecordId = $Event.RecordId

            EventId = $Event.Id

            Level = Protect-EventText `
                -Text ([string]$Event.LevelDisplayName)

            ProviderName = Protect-EventText `
                -Text ([string]$Event.ProviderName)

            Task = Protect-EventText `
                -Text ([string]$Event.TaskDisplayName)

            Opcode = Protect-EventText `
                -Text ([string]$Event.OpcodeDisplayName)

            Keywords = $SafeKeywords

            ProcessId = $Event.ProcessId

            ThreadId = $Event.ThreadId

            MachineName = $SafeMachineName

            UserId = $SafeUserId

            Message = $SafeMessage

            EventData = $SafeEventData
        }


        $Results.Add($Record)
    }


    # --------------------------------------------------------
    # SORT EVENTS CHRONOLOGICALLY
    # --------------------------------------------------------

    [array]$SortedResults = @(
        $Results |
        Sort-Object `
            TimeCreated,
            RecordId
    )


    # --------------------------------------------------------
    # WRITE CSV
    # --------------------------------------------------------

    $SortedResults |
        Export-Csv `
            -LiteralPath $CsvPath `
            -NoTypeInformation `
            -Encoding UTF8


    # --------------------------------------------------------
    # WRITE JSON
    #
    # Using -InputObject preserves a JSON array even if the
    # EVTX contains only one event.
    # --------------------------------------------------------

    $Json = ConvertTo-Json `
        -InputObject $SortedResults `
        -Depth 6


    $Json |
        Set-Content `
            -LiteralPath $JsonPath `
            -Encoding UTF8


    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    $SuccessfulFiles++

    $TotalEvents += $SortedResults.Count


    Write-Host ""
    Write-Host "Created:"
    Write-Host "  $CsvPath"
    Write-Host "  $JsonPath"
    Write-Host ""
}


# ============================================================
# FINISHED
# ============================================================

Write-Host "=============================================="
Write-Host "Sanitization complete"
Write-Host "=============================================="
Write-Host ""
Write-Host "Ticket:"
Write-Host "  $TicketNumber"
Write-Host ""
Write-Host "Local sanitization timestamp:"
Write-Host "  $LocalTimestamp"
Write-Host ""
Write-Host "EVTX files found:"
Write-Host "  $($EvtxFiles.Count)"
Write-Host ""
Write-Host "Successfully processed:"
Write-Host "  $SuccessfulFiles"
Write-Host ""
Write-Host "Files with errors:"
Write-Host "  $FailedFiles"
Write-Host ""
Write-Host "Total events exported:"
Write-Host "  $TotalEvents"
Write-Host ""
Write-Host "The original EVTX files were not modified."
Write-Host ""

Write-Warning (
    "Automated sanitization cannot guarantee removal of all " +
    "PHI, PII, customer names, patient names, filenames, case " +
    "names, or other free-form sensitive information. Review " +
    "sanitized output before uploading regulated data."
)