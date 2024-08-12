import fitz  # PyMuPDF
import yara
import sys
import os
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load YARA rules
def load_yara_rules(filepath):
    try:
        return yara.compile(filepath=filepath)
    except yara.YaraSyntaxError as e:
        logging.error(f"Failed to compile YARA rules. Error: {e}")
        sys.exit(1)

rules = load_yara_rules('pdf_bhavesh.yar')

def print_matches(file_path, matches):
    if matches:
        logging.warning(f"{file_path} is potentially malicious.")
        for match in matches:
            logging.warning(f"Detected rule: {match.rule}")
    else:
        logging.info(f"{file_path} is clean.")

def scan_pdf(file_path):
    if not os.path.isfile(file_path):
        logging.error(f"The file '{file_path}' does not exist.")
        return

    try:
        pdf_document = fitz.open(file_path)
        pdf_text = ""
        for page_num in range(len(pdf_document)):
            page = pdf_document.load_page(page_num)
            pdf_text += page.get_text()
        matches = rules.match(data=pdf_text)
        print_matches(file_path, matches)
    except fitz.FileDataError:
        logging.warning(f"The file '{file_path}' is corrupted. Attempting to read raw data.")
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                matches = rules.match(data=file_data)
                print_matches(file_path, matches)
        except Exception as e:
            logging.error(f"Failed to read the corrupted file. Error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred while processing '{file_path}'. Error: {e}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Scan PDF files for potential threats using YARA rules.")
    parser.add_argument('files', metavar='file', type=str, nargs='+', help='PDF files to scan')
    return parser.parse_args()

def main():
    args = parse_arguments()
    if not args.files:
        logging.error("No files provided for scanning.")
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        future_to_file = {executor.submit(scan_pdf, file): file for file in args.files}
        for future in as_completed(future_to_file):
            file = future_to_file[future]
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error scanning file {file}: {e}")

if __name__ == "__main__":
    main()

