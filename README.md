# PDF Scanning Tool

## Overview

This tool is designed to scan PDF files for potential malicious content and generate detailed reports based on various types of analysis. It uses multiple libraries and techniques to achieve its goals, including:

PyMuPDF -  for text extraction and embedded file analysis
Yara - for rule-based malware detection

## Requirements

To use this tool, you need to have the following Python packages installed:

```bash
pip install PyMuPDF
sudo apt-get install yara
sudo apt-get install libyara-dev
pip install yara-python
```

You also need to have Yara installed and properly configured on your system.



## Functionality

### 1. Extract Text from PDF using PyMuPDF

Function: `extract_text_pymupdf(pdf_path)`
Description: Extracts all the text from a PDF file using PyMuPDF.

Parameters:
- `pdf_path` (str): Path to the PDF file.


Returns:
- `text` (str): Extracted text from the PDF.

Exceptions: Handles and prints any errors encountered during extraction.


### 2. Scan File with Yara

Function:  `scan_with_yara(file_path, rules)`

Description:  Scans a file for malicious patterns based on Yara rules.

Parameters: `file_path` (str): 
 Path to the file.
 `rules` (yara.Rules): Yara rules object compiled from rule files.

Returns:
`is_match` (bool): `True` if any Yara rules match, otherwise `False`.
 `matches_list` (list of dicts or None): Detailed match information if matches are found.

Exceptions: Handles and prints any errors encountered during scanning.


### Command Line Usage

To run the tool from the command line, use the following syntax:

```bash
python <script_name>.py <pdf_path>
```

Parameters:
- `<script_name>.py`: Name of the Python script file.
- `<pdf_path>`: Path to the PDF file you want to scan.

 #### Example

```bash
python pdf_scanner.py example.pdf
```

### Facing Issues - Use Venv
Using a Virtual Environment
Creating and using a virtual environment is often the easiest and safest approach. This isolates your Python packages from the system packages, preventing conflicts.

Create a Virtual Environment:
```bash
python3 -m venv path/to/venv
```
Activate the Virtual Environment:
```bash
source path/to/venv/bin/activate
```
Deactivate the Virtual Environment:
```bash
deactivate
```

This documentation should provide a comprehensive understanding of how to use the tool, its functions, and how to interpret its outputs.
### Description of Our PDF Scanning Tool
Our tool is designed to scan PDF files for security threats by checking them against a set of predefined YARA rules. The tool performs the following functions:

### PDF Scanning: 
It opens and extracts text from the specified PDF file.
### YARA Rule Checking:
The extracted text is analyzed using multiple YARA rules, which are designed to detect specific patterns or behaviors that may indicate malicious content or vulnerabilities.
### Detection and Reporting: 
If the tool detects any matches with the YARA rules, it will report that the PDF is potentially insecure or corrupted. It will then specify which YARA rule(s) were triggered.
What Are YARA Rules?

### YARA (Yet Another Recursive Acronym) 
is a tool used to identify and classify malware samples based on specific patterns and characteristics. YARA rules are used to define these patterns, which can include text strings, byte sequences, or other data patterns that may be indicative of malicious behavior. 
