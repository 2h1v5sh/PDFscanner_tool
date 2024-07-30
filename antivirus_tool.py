import fitz  # PyMuPDF
import yara
import sys
import os

# Load YARA rules
rules = yara.compile(filepath='pdf_bhavesh.yar')

def scan_pdf(file_path):
    # Check if file exists
    if not os.path.isfile(file_path):
        print(f"The file '{file_path}' does not exist.")
        return

    def print_matches(matches):
        if matches:
            print(f"{file_path} is potentially malicious.")
            for match in matches:
                print(f"Detected rule: {match.rule}")
        else:
            print(f"{file_path} is clean.")

    try:
        # Open the PDF file
        pdf_document = fitz.open(file_path)
        
        # Extract the text from each page
        pdf_text = ""
        for page_num in range(len(pdf_document)):
            page = pdf_document.load_page(page_num)
            pdf_text += page.get_text()

        # Scan the extracted text with YARA rules
        matches = rules.match(data=pdf_text)
        print_matches(matches)
    
    except fitz.FileDataError:
        print(f"The file '{file_path}' is corrupted and not safe.")
        # Attempt to read the raw file data
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                matches = rules.match(data=file_data)
                print_matches(matches)
        except Exception as e:
            print(f"Failed to read the corrupted file. Error: {e}")
    except Exception as e:
        print(f"The file '{file_path}' is corrupted and not safe. Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan_pdf.py <file_path>")
    else:
        scan_pdf(sys.argv[1])

