# Nessus HTML to CSV Converter

A PowerShell utility designed to parse **Tenable Nessus** HTML reports and convert them into a structured, Excel-friendly CSV format. 

This tool is particularly useful when you only have access to the HTML report file and need to filter, sort, or analyze the vulnerability data programmatically or within a spreadsheet.

## 🚀 Features

* **HTML Parsing:** Extracts Host IP, Risk Factor, CVSS Scores, Synopsis, Description, Solution, and more from Nessus HTML reports.
* **Smart Parsing:**
    * **Protocol & Port Extraction:** Automatically parses Nessus service tags (e.g., `tcp/2282/ssh`) and splits them into distinct `Layer-4 Protocol`, `Layer-7 Protocol`, and `Port` columns.
    * **Risk Factor Detection:** Identifies risk levels (Critical, High, Medium, etc.) based on Nessus color coding for 100% accuracy.
    * **Reference Splitting:** Separates CVE IDs and other references (XREF, RHSA, etc.) into distinct columns.
* **Auto-Rename Output:** Output file parameters are optional. The script can automatically generate a `.csv` file with the exact same base name as your input `.html` file.
* **Excel Safety:**
    * **Character Limiting:** Automatically splits long "Plugin Outputs" into multiple columns (`Plugin Output 1` to `5`) to avoid Excel's 32,767 character cell limit.
    * **Format Cleaning:** Sanitizes HTML tags and special characters for clean CSV output without breaking rows.
* **Performance:** Optimized regex logic to handle large HTML files without hanging/freezing.

## 📋 Prerequisites

* Windows OS with **PowerShell 5.1** or newer.
* `.NET Framework` (standard on Windows) for HTML decoding.

## 🛠️ Usage

1. Download the script (`Convert-Nessus.ps1`).
2. Open PowerShell in the directory where the script is located.
3. Run the script with the input HTML file. 

**Option 1: Auto-generate output file name (Recommended)**
```powershell
.\Convert-Nessus.ps1 -InputFile "report.html"
