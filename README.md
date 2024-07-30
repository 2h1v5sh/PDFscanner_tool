## Description of Our PDF Scanning Tool
Our tool is designed to scan PDF files for security threats by checking them against a set of predefined YARA rules. The tool performs the following functions:

PDF Scanning: It opens and extracts text from the specified PDF file.
YARA Rule Checking: The extracted text is analyzed using multiple YARA rules, which are designed to detect specific patterns or behaviors that may indicate malicious content or vulnerabilities.
Detection and Reporting: If the tool detects any matches with the YARA rules, it will report that the PDF is potentially insecure or corrupted. It will then specify which YARA rule(s) were triggered.
What Are YARA Rules?
YARA (Yet Another Recursive Acronym) is a tool used to identify and classify malware samples based on specific patterns and characteristics. YARA rules are used to define these patterns, which can include text strings, byte sequences, or other data patterns that may be indicative of malicious behavior. These rules help in:

Malware Detection: By defining patterns that are commonly found in malware, YARA rules can help identify malicious files.
Threat Classification: They can classify threats based on their behavior or characteristics, facilitating better analysis and response.
Tool Functionality
When our tool scans a PDF file:

It first attempts to open and extract text from the file.
The extracted text is then compared against a set of YARA rules.
If any matches are found, the tool will print a message indicating that the PDF is potentially insecure or corrupted.
Additionally, it will specify which YARA rule(s) were detected, providing insights into the nature of the potential threat.
