# Nessus HTML to CSV Converter

A PowerShell utility designed to parse **Tenable Nessus** HTML reports and convert them into a structured, Excel-friendly CSV format. 

This tool is particularly useful when you only have access to the HTML report file and need to filter, sort, or analyze the vulnerability data programmatically or within a spreadsheet.

## 🚀 Features

* **HTML Parsing:** Extracts Host IP, Risk Factor, CVSS Scores, Synopsis, Description, and Solution from Nessus HTML reports.
* **Smart Parsing:**
    * **Risk Factor Detection:** Identifies risk levels (Critical, High, Medium, etc.) based on Nessus color coding for accuracy.
    * **Reference Splitting:** Separates CVE IDs and other references (XREF, RHSA, etc.) into distinct columns.
* **Excel Safety:**
    * **Character Limiting:** Automatically splits long "Plugin Outputs" into multiple columns (`Plugin Output 1` to `5`) to avoid Excel's 32,767 character cell limit.
    * **Format Cleaning:** Sanitizes HTML tags and special characters for clean CSV output.
* **Performance:** Optimized regex logic to handle large HTML files without hanging/freezing.

## 📋 Prerequisites

* Windows OS with **PowerShell 5.1** or newer.
* `.NET Framework` (standard on Windows) for HTML decoding.

## 🛠️ Usage

1.  Download the script (`Convert-Nessus.ps1`).
2.  Open PowerShell in the directory where the script is located.
3.  Run the script with the input HTML file and desired output CSV name.

```powershell
.\Convert-Nessus.ps1 -InputFile "report.html" -OutputFile "report.csv"
```

Handling Execution Policy Error
If you encounter an error saying scripts are disabled, run this command before executing the script:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

## 📝 Output Columns
* The generated CSV will contain:
* Host IP
* Risk Factor (Critical, High, Medium, Low, Info)
* Vulnerability Name
* CVSS v3.0 Base & Temporal Scores
* CVE (List of CVE IDs)
* XREF (External References)
* Synopsis & Description
* Solution
* Exploitable With
* Plugin Information
* Plugin Output (Split into multiple columns if too long)

## ⚠️ Disclaimer
This tool is provided "as is" without warranty of any kind. It is intended to assist security professionals in managing vulnerability data.
