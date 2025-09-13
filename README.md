
# Microsoft Vulnerable Driver Block Lists

Microsoft no longer provides the vulnerable driver block list in a browsable web page; instead, the list is only available as a downloadable ZIP file. This change makes it difficult to use the block list directly in SIEM products for lookups or other purposes.

This project automates the process of downloading the latest VulnerableDriverBlockList ZIP file, extracting and parsing the `SiPolicy_Enforced.xml` file, and transforming the data into CSV and JSON formats for easy integration with SIEM and other security tools.

## Key Features
- **Automated Download**: Fetches the latest block list ZIP from Microsoft using GitHub Actions.
- **XML Parsing & Data Cleaning**: Parses `<FileRules>` in `SiPolicy_Enforced.xml` and extracts key driver information.
- **Reliable Filename & Hash Extraction**: The `FriendlyName` field in the XML contains both the filename and the SHA256 hash, but this information is not always reliably formatted. The script attempts to fix inconsistencies and reliably extract both the filename and the file SHA256 hash (stored in the `FileHash` column).
- **Authentihash**: The `Hash` value in the XML is the Authentihash of the driver. The Authentihash is a cryptographic hash used by Windows to uniquely identify a signed driver file, regardless of its signature format. The `Hash` field is renamed to `Authentihash` to avoid confusion.
- **Base64 SHA256 Representation**: The script also generates a base64 representation of the file SHA256 (`b64FileHash`), which may be useful for matching(the `AdditionalFields` column in Microsoft Defender for Endpoint (MDE) DriverLoad events have base64 represantation of the file hash values).
- **Weekly Updates**: The CSV and JSON files are updated weekly to ensure you have the latest block list data.

## Limitations
- Not all drivers in the block list contain file hash information. The script will leave these fields empty when data is unavailable.

## Output Fields
- `ID`: Rule identifier
- `FriendlyName`: Original descriptive name from XML
- `FileName`: Extracted filename (corrected if necessary) from the `FriendlyName`
- `Authentihash`: `Hash` value from XML (renamed column to avoid confusion)
- `FileHash`: Extracted file SHA1/SHA256 from the FriendlyName (if available)
- `b64FileHash`: Base64 representation of the file SHA1/SHA256 (if available)
- `MinimumFileVersion`: Used in File attribute rules 
- `MaximumFileVersion`: Used in File attribute rules 
- `InternalName`: Used in File attribute rules 
- `ProductName`: Used in File attribute rules 

## Usage
1. Use the generated CSV/JSON files for lookups in SIEM, EDR, or other security platforms.


---
# References
-  [Microsoft Vulnerable Driver Block List](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml).
