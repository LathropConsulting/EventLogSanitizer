# Windows Event Log Sanitizer

A PowerShell utility for converting downloaded Windows `.evtx` files into sanitized CSV and JSON files suitable for troubleshooting, documentation, or analysis with AI tools such as ChatGPT.

The script is designed for offline use. It reads only EVTX files that have already been downloaded to the computer running the script and does not query or modify the computer's live Windows Event Logs.

## Features

* Processes downloaded `.evtx` files from a specified folder.

* Keeps each Windows Event Log separate.

* Creates one sanitized CSV and one sanitized JSON file per EVTX file.

* Leaves the original EVTX files unchanged.

* Requires a PSA or case ticket number in the format:

  `TYYYYMMDD.####`

* Uses the internal Windows Event Log channel name for output filenames instead of trusting the original EVTX filename.

* Adds a compact local ISO 8601 timestamp including the local UTC offset.

* Uses consistent one-way pseudonyms within each execution.

* Generates a new random pseudonymization salt for each execution.

* Redacts or pseudonymizes common sensitive values.

* Supports optional user-supplied sensitive terms.

* Preserves Event Log metadata useful for troubleshooting.

* Exports both rendered event messages and underlying event property data when available.

## Requirements

* Windows
* Windows PowerShell 5.1 or PowerShell 7+
* Access to the downloaded `.evtx` files
* Permission to read the folder containing the EVTX files

No additional PowerShell modules are required.

The script relies primarily on built-in Windows and .NET functionality, including:

```text
Get-WinEvent
System.Security.Cryptography
System.Net.IPAddress
ConvertTo-Json
Export-Csv
```

## Installation

Save the script as:

```text
EventLogSanitizer.ps1
```

For example:

```text
C:\Tools\EventLogSanitizer.ps1
```

No installation process is otherwise required.

If PowerShell execution policy prevents the script from running, review the current policy before changing it:

```powershell
Get-ExecutionPolicy -List
```

Avoid weakening the system-wide PowerShell execution policy unnecessarily.

## Basic Usage

Place the downloaded EVTX files into a dedicated folder.

Example:

```text
C:\EventLogs\
    Application.evtx
    System.evtx
```

Run:

```powershell
.\EventLogSanitizer.ps1 `
    -FolderPath "C:\EventLogs" `
    -TicketNumber "T20260922.0001"
```

The script processes each EVTX file independently.

## Parameters

### `-FolderPath`

Required.

Specifies the folder containing the downloaded `.evtx` files.

Example:

```powershell
-FolderPath "C:\EventLogs"
```

Only EVTX files directly inside the specified folder are processed.

Subfolders are not searched.

### `-TicketNumber`

Required.

Specifies the ticket or case number associated with the analysis.

Required format:

```text
TYYYYMMDD.####
```

Example:

```text
T20260922.0001
```

The ticket number becomes the first component of every generated filename.

### `-SensitiveTerms`

Optional.

Specifies additional customer-specific, case-specific, or otherwise sensitive values that should be pseudonymized.

Examples may include:

* Customer names
* Organization names
* Internal domains
* Public domains
* Usernames
* Server names
* Patient names
* Client names
* Case names
* Matter names
* Project names

Example:

```powershell
.\EventLogSanitizer.ps1 `
    -FolderPath "C:\EventLogs" `
    -TicketNumber "T20260922.0001" `
    -SensitiveTerms @(
        "Example Medical Practice",
        "example.local",
        "example.com",
        "John Smith"
    )
```

When possible, provide known sensitive terms before processing regulated or confidential Event Logs.

## Output Files

Each EVTX file generates its own CSV and JSON file.

Output filename format:

```text
<Ticket>_<LocalTimestamp>_<EventLog>_Sanitized.<extension>
```

Example:

```text
T20260922.0001_20260922T160356-0500_Application_Sanitized.csv
T20260922.0001_20260922T160356-0500_Application_Sanitized.json

T20260922.0001_20260922T160356-0500_System_Sanitized.csv
T20260922.0001_20260922T160356-0500_System_Sanitized.json
```

The filename identifies:

* The associated ticket
* When sanitization occurred
* The Windows Event Log type
* That the file contains sanitized data

## Timestamp Format

The sanitization timestamp uses local time with the UTC offset.

Format:

```text
YYYYMMDDTHHMMSS±HHMM
```

Example:

```text
20260922T160356-0500
```

This provides the readability of local time while keeping the timestamp unambiguous.

The UTC offset automatically reflects the system's current time-zone configuration, including daylight-saving changes where applicable.

The timestamp is generated once per execution, so all files created during the same run share the same timestamp.

## Event Log Naming

The script does not use the downloaded EVTX filename when constructing sanitized output filenames.

Instead, it reads the Windows Event Log channel name stored inside the EVTX data.

For example:

```text
Application
```

or:

```text
Microsoft-Windows-TaskScheduler/Operational
```

Characters that are not valid in Windows filenames are converted to underscores.

For example:

```text
Microsoft-Windows-TaskScheduler/Operational
```

becomes:

```text
Microsoft-Windows-TaskScheduler_Operational
```

This reduces the risk of exposing customer information if the original EVTX filename contains identifying data.

## Sanitized Fields

The output retains troubleshooting-relevant fields such as:

```text
LogName
TimeCreated
RecordId
EventId
Level
ProviderName
Task
Opcode
Keywords
ProcessId
ThreadId
MachineName
UserId
Message
EventData
```

The JSON and CSV versions contain the same logical event records.

## EventData

When an EVTX file is opened on a computer that does not have the original software or event provider installed, Windows may be unable to render the normal event message.

In those cases, the event may contain a message such as:

```text
The description for Event ID ... cannot be found
```

or the message may be unavailable entirely.

The script therefore also exports the values contained in:

```powershell
$Event.Properties
```

These values are placed into the `EventData` field after sanitization.

This can preserve useful diagnostic data even when the rendered message is unavailable.

Binary event-property values are not exported directly and are represented as:

```text
[BINARY-DATA]
```

## Pseudonymization

Identifying values are replaced with pseudonyms such as:

```text
[HOST-A1B2C3D4E5]
[PRIVATE-IP-1234567890]
[PUBLIC-IP-ABCDEF1234]
[EMAIL-456789ABCD]
[ACCOUNT-9876543210]
[SID-1122334455]
[MAC-AABBCCDDEE]
[CUSTOM-FFEEDDCCBB]
```

The exact token values will vary.

### Consistency Within a Run

The same original value receives the same pseudonym throughout a single execution.

For example, if one private IP address appears in 50 events, it will receive the same pseudonym in all 50 events.

This allows event correlation without retaining the original value.

### Separation Between Runs

A cryptographically random salt is generated each time the script runs.

The salt is not saved.

As a result, the same original value will normally receive a different pseudonym during a later execution.

This reduces the ability to correlate sanitized identifiers across unrelated cases or customers.

## Data Automatically Sanitized

The script attempts to detect and sanitize or redact values including:

* Computer names
* Windows accounts
* User-profile names
* Windows SIDs
* Email addresses
* IPv4 addresses
* IPv6 addresses
* MAC addresses
* URLs
* UNC paths
* Password-like fields
* API keys
* Authentication tokens
* JWTs
* Common access-key formats
* User-specified sensitive terms

## IP Addresses

The script distinguishes between common IPv4 address classes for labeling purposes.

Examples:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

are pseudonymized using:

```text
[PRIVATE-IP-*]
```

Public IPv4 addresses use:

```text
[PUBLIC-IP-*]
```

Link-local IPv4 addresses use:

```text
[LINKLOCAL-IP-*]
```

IPv6 addresses use:

```text
[IPV6-*]
```

Common generic addresses such as the following may be retained because they normally do not identify a specific endpoint:

```text
0.0.0.0
127.0.0.1
255.255.255.255
::1
```

## Credentials and Secrets

Values that appear to be credentials or authentication secrets are redacted instead of pseudonymized.

Examples include:

```text
Authorization: Bearer ...
password=...
client_secret=...
api_key=...
access_token=...
refresh_token=...
```

These are replaced with values such as:

```text
[REDACTED-SECRET]
[REDACTED-JWT]
[REDACTED-AWS-KEY]
[REDACTED-GITHUB-TOKEN]
```

The original secret is not intentionally preserved in the output.

## Example Workflow

Suppose the folder contains:

```text
C:\EventLogs\
    Application.evtx
    System.evtx
    Microsoft-Windows-Kernel-Power-Operational.evtx
```

Run:

```powershell
.\EventLogSanitizer.ps1 `
    -FolderPath "C:\EventLogs" `
    -TicketNumber "T20260922.0001"
```

The resulting folder may contain:

```text
Application.evtx
System.evtx
Microsoft-Windows-Kernel-Power-Operational.evtx

T20260922.0001_20260922T160356-0500_Application_Sanitized.csv
T20260922.0001_20260922T160356-0500_Application_Sanitized.json

T20260922.0001_20260922T160356-0500_System_Sanitized.csv
T20260922.0001_20260922T160356-0500_System_Sanitized.json

T20260922.0001_20260922T160356-0500_Microsoft-Windows-Kernel-Power_Operational_Sanitized.csv
T20260922.0001_20260922T160356-0500_Microsoft-Windows-Kernel-Power_Operational_Sanitized.json
```

The EVTX files remain unchanged.

## CSV vs. JSON

Both formats contain the same event records.

### JSON

JSON is generally preferred for AI-assisted Event Log analysis because it preserves structured records cleanly and handles multiline messages well.

Use JSON when uploading logs to ChatGPT or another structured-data analysis system.

### CSV

CSV is useful for:

* Excel
* Sorting and filtering
* Manual review
* Searching
* Pivot tables
* Simple scripting and reporting

The CSV also provides a convenient way to manually inspect the sanitized data before uploading it elsewhere.

## Recommended AI Analysis Workflow

A recommended workflow is:

1. Obtain the required EVTX files from the affected system.
2. Store them in a dedicated folder associated with the ticket.
3. Run the sanitizer locally.
4. Review the sanitized CSV or JSON output.
5. Upload only the required sanitized JSON files.
6. Start with the minimum Event Logs needed for the investigation.
7. Upload additional logs only when they are useful for correlation or troubleshooting.
8. Keep the original EVTX files local unless there is a specific need to transfer them.

For example, start with:

```text
System
```

or:

```text
Application
```

instead of uploading every available Windows Event Log.

## Security Model

The sanitizer is intended to reduce unnecessary exposure of identifying information before Event Log data is shared with another system.

Its primary security principles are:

* Data minimization
* Local processing
* Independent per-log output
* Pseudonymization
* Secret redaction
* No pseudonym lookup table
* No saved pseudonymization salt
* Preservation of troubleshooting context where possible

The original EVTX files are read locally and are not modified by the script.

## Important Security Limitations

Automated sanitization cannot guarantee complete removal of sensitive information.

Windows Event Log messages are free-form data and may contain arbitrary values that cannot reliably be identified with regular expressions.

Examples include:

* Patient names
* Customer names
* Employee names
* Legal matter names
* Medical information
* Document names
* File names
* Folder names
* Database names
* Application-specific identifiers
* Account numbers
* Proprietary information
* PHI
* PII
* Confidential business information

For regulated or highly confidential environments:

1. Use `-SensitiveTerms` for known identifiers.
2. Review the resulting CSV or JSON manually.
3. Upload only the Event Logs required for the investigation.
4. Do not assume that sanitization alone satisfies regulatory or contractual requirements.
5. Do not upload the original EVTX unless there is a specific and appropriate reason to do so.

## Original Files

The script does not intentionally:

* Modify source EVTX files
* Delete source EVTX files
* Rename source EVTX files
* Clear Windows Event Logs
* Export live Windows Event Logs
* Upload files anywhere
* Transmit data over the network

All sanitization occurs locally.

## Exit Behavior

A successful execution completes after processing all readable EVTX files.

The console reports:

* Ticket number
* Sanitization timestamp
* Number of EVTX files found
* Number successfully processed
* Number that encountered errors
* Total number of events exported
* Output filenames

If an individual EVTX file cannot be read, the script reports the error and continues with the remaining files.

If no EVTX files exist in the supplied folder, the script stops with an error.

If no events can be read from a particular EVTX file, that file is not exported.

## Troubleshooting

### No EVTX files found

Verify that:

* `-FolderPath` points to the correct directory.
* Files use the `.evtx` extension.
* The EVTX files are directly inside the specified folder rather than a subfolder.

### EVTX file cannot be read

Try opening the file in Windows Event Viewer.

You can also test it with:

```powershell
Get-WinEvent -Path "C:\EventLogs\System.evtx" -MaxEvents 10
```

If this fails, the EVTX may be damaged, inaccessible, or unsupported.

### Event messages are unavailable

Downloaded EVTX files sometimes reference message resources installed only on the originating computer.

This is expected behavior.

The sanitizer exports the underlying event-property values into `EventData` when available so useful diagnostic information may still be preserved.

### Output filename contains `UnknownEventLog`

This means the script could not obtain a usable internal `LogName` from the EVTX.

The original filename is intentionally not used as a fallback because it may contain identifying information.

### Expected identifying value was not removed

Add the value explicitly with:

```powershell
-SensitiveTerms
```

Example:

```powershell
-SensitiveTerms @(
    "Example Company",
    "EXAMPLE-SERVER",
    "example.local"
)
```

Then review the regenerated sanitized files.

### Pseudonyms changed after rerunning the script

This is expected.

A new random salt is created for every execution.

Pseudonyms remain consistent only within the same sanitization run.

## Privacy Recommendation

Treat sanitization as one layer of a broader data-handling process.

A strong workflow combines:

* Collecting only necessary Event Logs
* Sanitizing locally
* Reviewing the sanitized output
* Uploading only relevant log types
* Using appropriate privacy and retention controls in the destination system
* Removing analysis files when they are no longer needed
* Retaining original evidence according to applicable organizational policy

## Disclaimer

This utility is intended to assist with data minimization and pseudonymization. It is not a guarantee of complete de-identification, anonymization, regulatory compliance, or removal of all confidential information.

Review the generated output before sharing it with any third party or external service.
