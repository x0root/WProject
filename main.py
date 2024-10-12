import argparse
import subprocess
import sys
import os
import time
import tabulate
from colorama import Fore, Style
from urllib.parse import urlparse  # Moved import to the top for clarity
import textwrap  # Import textwrap for wrapping text
import nmap3
from tabulate import tabulate  # Ensure tabulate is imported
import html

# Define a class to capture stdout and stderr
class OutputToHTML:
    def __init__(self, original_stdout, original_stderr, file_name="output.html"):
        self.original_stdout = original_stdout
        self.original_stderr = original_stderr
        self.file_name = file_name  # Fixed the reference to file_name
        self.output_buffer = []
    def write(self, data):
        # Escape special HTML characters and store them in the buffer
        escaped_data = html.escape(data)
        self.output_buffer.append(escaped_data)
        # Also print to the original terminal output (if you want)
        self.original_stdout.write(data)
    
    def flush(self):
        pass
    
    def save_output(self):
        # Save the output buffer to an HTML file
        with open(self.file_name, 'w') as f:
            f.write("<html><body><pre>\n")
            f.write("".join(self.output_buffer))
            f.write("\n</pre></body></html>")

# Replace sys.stdout and sys.stderr
original_stdout = sys.stdout
original_stderr = sys.stderr
output_capturer = OutputToHTML(original_stdout, original_stderr)

sys.stdout = output_capturer
sys.stderr = output_capturer

# Register function to save output when program exits
def save_output_on_exit():
    output_capturer.save_output()

import atexit  # Import atexit here to ensure it's defined
atexit.register(save_output_on_exit)  # Register the function after importing

def run_command_with_timeout(command, timeout):
    try:
        # Run the command and capture output in real-time
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip()  # Return both stdout and stderr
    except subprocess.TimeoutExpired:
        return None, f"Command '{' '.join(command)}' timed out and was killed."
    except Exception as e:
        return None, str(e)  # Capture any other exceptions

def main():
    # Display the banner in red
    banner = Fore.RED + "       __  __  __     ___ _____ \n" \
                     " (   //__)/__)/  )  /(_  / )/   \n" \
                     " |/|//   / ( (__/(_/ /__(__(    \n" + Style.RESET_ALL
    print(banner)
    print()
    print("V.10")
    print("Made by x0root")

    parser = argparse.ArgumentParser(description='Automated scanning tool.')
    parser.add_argument('-u', '--domain', required='--gui' not in sys.argv, help='The domain to scan')
    parser.add_argument('--auto', action='store_true', help='Run automated scans')
    parser.add_argument('--random-agent', action='store_true', help='Use a random user agent for requests')
    parser.add_argument('--fbypass', action='store_true', help='Bypass 403')
    parser.add_argument('--cleanup', action='store_true', help='Delete subdomains.txt and output.html after use')
    parser.add_argument('--gui', action='store_true', help='Start a Flask web server and serve index.html')

    def start_flask_server():
        from flask import Flask, send_from_directory, request, Response
        import json
        import subprocess

        app = Flask(__name__)

        @app.route('/web/index.html')
        def serve_index():
            return send_from_directory('web', 'index.html')

        @app.route('/')
        def root():
            return serve_index()
        
        @app.route('/execute', methods=['POST'])
        def execute_command():
            data = json.loads(request.data)
            domain = data.get('domain')
            parameters = data.get('parameters', [])

            # Build the command dynamically
            command = ['python', 'main.py', '-u', domain] + parameters

            # Run the command in real-time and stream the output back to the frontend
            def generate():
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                for line in iter(process.stdout.readline, b''):
                    yield line.decode('utf-8')
                process.stdout.close()

            return Response(generate(), mimetype='text/plain')

        app.run(host='127.0.0.1', port=5000)

    args = parser.parse_args()
    if args.gui:
        start_flask_server()
        sys.exit(0)

    def cleanup_files(subdomains_file='subdomains.txt', output_file='output.html'):
        """Delete the specified subdomains file and output file if they exist."""
        try:
            for file_path in [subdomains_file, output_file]:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    print(f"Deleted {file_path}.")
                else:
                    print(f"{file_path} does not exist.")
        except Exception as e:
            print(f"Error deleting files: {str(e)}")

    args = parser.parse_args()  # Ensure args is defined before use
    if args.cleanup:
        cleanup_files()  # Call the cleanup function if the flag is set
    args = parser.parse_args()  # Move this line up to ensure args is defined before use
    if args.fbypass:
        command = ['python3', 'forbiddenpass.py', '-t', domain]  # Use args.domain instead of domain
        stdout, stderr = run_command(command)
        print(f"Running: {' '.join(command)}")  # Print the command being run
        print(f"Output: {stdout}")  # Print the output
        print(f"Error: {stderr}")  # Print any errors
        sys.exit(0)  # Exit after running the command

    args = parser.parse_args()

    if args.domain is None:
        print("Expected one argument: the domain to scan.")
        sys.exit(1)

    domain = args.domain  # Assign the domain from the parsed arguments
    if domain:
        # Remove any subdomains to get the main domain
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            domain = '.'.join(domain_parts[-2:])

    if args.auto:
        results = []

        import subprocess

        def run_command(command):
            command_output = ""
            command_error = ""
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                command_output, command_error = process.communicate(timeout=15)  # Set timeout to 15 seconds
            except subprocess.TimeoutExpired:
                print(f"Command '{' '.join(command)}' exceeded 15 seconds and will be forcibly terminated.")
                process.kill()  # Forcefully terminate the process
                command_output, command_error = process.communicate()  # Capture any output after termination
                return None, "Timeout"
            return command_output.strip(), command_error.strip()
        
        print("====Performing Basic Scan====")

        commands = [
            (['python3', 'scan.py', '-or', args.domain, '-v', '-c', '50'], "OR Scan"),
            (['python3', 'scan.py', '-fi', args.domain], "FavIcon hashes"),
            (['python3', 'scan.py', '-javascript', args.domain], "Broken Link"),
            (['python3', 'SWS-Recon.py', '--whois', '-d', domain], "Whois"),
            (['python3', 'SWS-Recon.py', '-t', '-d', domain], "Technologies"),
            (['python3', 'SWS-Recon.py', '-a', '-d', domain], "Domain zone transfer attack"),
        ]

        for command_info in commands:
            command = command_info[0]
            description = command_info[1] if len(command_info) > 1 else "No description"
            stdout, stderr = run_command(command)  # Use the existing run_command function
            print(f"Running: {' '.join(command)}")  # Print the command being run
            print(f"Output: {stdout}")  # Print the output
            print(f"Error: {stderr}")  # Print any errors
            results.append([description, stdout if stdout else "Error", stderr if stderr else ""])

        print("====Performing Subfinder Scan====")

        # Extract the domain from the provided URL
        parsed_url = urlparse(args.domain)
        domain = parsed_url.hostname

        if domain:
            # Remove any subdomains to get the main domain
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                domain = '.'.join(domain_parts[-2:])
            subfinder_result = run_command_with_timeout(['subfinder', '-d', domain, '-o', 'subdomains.txt'], timeout=30)
            results.append(["Subfinder", subfinder_result[0] if subfinder_result[0] else "Error", subfinder_result[1] if subfinder_result[1] else ""])

        print("====Performing HTTPX Scan====")

        httpx_result = run_command_with_timeout(['httpx', '-sc', '-td', '-title', '-probe', '-fhr', '-location', '-list', 'subdomains.txt'], timeout=50)
        results.append(["HTTPX Scan", httpx_result[0] if httpx_result[0] else "Error", httpx_result[1] if httpx_result[1] else ""])

        print("====Performing WAF Scan====")

        waf_result = run_command_with_timeout(['python3', 'waf/identYwaf.py', '--random-agent', domain], timeout=30)
        results.append(["WAF Identification", waf_result[0] if waf_result[0] else "Error", waf_result[1] if waf_result[1] else ""])

        print("====Performing Nuclei Scan====")

        # Flatten Nuclei results
        nuclei_results = []
        nuclei_commands = [
            (['nuclei', '-u', args.domain, '-t', 'http/cves/2024/CVE-2024-44000.yaml', 'http/cves/2024/CVE-2024-20419.yaml', 'javascript/cves/2024/CVE-2024-47176.yaml', 'http/cves/2024/CVE-2024-27564.yaml', 'http/cves/2024/CVE-2024-34351.yaml', 'http/cves/2024/CVE-2024-38472.yaml'], "Nuclei CVE Scans"),
            (['nuclei', '-u', domain], "Nuclei Default Templates"),
        ]

        for command, description in nuclei_commands:
            stdout, stderr = run_command_with_timeout(command, timeout=30)  # Set timeout to 30 seconds
            print(f"Running: {' '.join(command)}")  # Print the command being run
            print(f"Output: {stdout}")  # Print the output
            print(f"Error: {stderr}")  # Print any errors
            results.append([description, stdout if stdout else "Error", stderr if stderr else ""])
        
        print("")
        print("=====Scan Result=====")
        print("")
        # Print results in a compact table format
        max_output_length = 50  # Set a maximum length for output and error messages
        compact_results = []
        for result in results:
            description, output, error = result
            
            # Wrap the output and error messages
            wrapped_output = "\n".join(textwrap.wrap(output, width=max_output_length))
            wrapped_error = "\n".join(textwrap.wrap(error, width=max_output_length))
            
            compact_results.append([
                description,
                wrapped_output,
                wrapped_error
            ])

        # Print the table with specified column widths and padding
        print(tabulate(compact_results, headers=["Scan Type", "Output", "Error"], tablefmt="grid", maxcolwidths=[20, 50, 50], stralign="left", numalign="left"))

if __name__ == '__main__':
    main()