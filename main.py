import argparse
import subprocess
import sys
import time
import tabulate
from colorama import Fore, Style
from urllib.parse import urlparse  # Moved import to the top for clarity
import textwrap  # Import textwrap for wrapping text
import nmap3
from tabulate import tabulate  # Ensure tabulate is imported

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
    parser.add_argument('domain', nargs='?', help='The domain to scan')
    parser.add_argument('--auto', action='store_true', help='Run automated scans')

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

        commands = [
            (['python3', 'spyhunt.py', '-or', args.domain, '-v', '-c', '50'], "Other Scan"),  # Added timeout of 18 seconds
        ]

        for command_info in commands:
            command = command_info[0]
            description = command_info[1] if len(command_info) > 1 else "No description"
            stdout, stderr = run_command_with_timeout(command, timeout=30)  # Set timeout to 30 seconds
            print(f"Running: {' '.join(command)}")  # Print the command being run
            print(f"Output: {stdout}")  # Print the output
            print(f"Error: {stderr}")  # Print any errors
            results.append([description, stdout if stdout else "Error", stderr if stderr else ""])

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

            httpx_result = run_command_with_timeout(['httpx', '-sc', '-td', '-title', '-probe', '-fhr', '-location', '-list', 'subdomains.txt'], timeout=30)
            results.append(["HTTPX Scan", httpx_result[0] if httpx_result[0] else "Error", httpx_result[1] if httpx_result[1] else ""])

        waf_result = run_command_with_timeout(['python3', 'waf/identYwaf.py', '--random-agent', domain], timeout=30)
        results.append(["WAF Identification", waf_result[0] if waf_result[0] else "Error", waf_result[1] if waf_result[1] else ""])

        # Flatten Nuclei results
        nuclei_results = []
        nuclei_commands = [
            (['nuclei', '-u', args.domain, '-t', 'http/cves/2024/CVE-2024-44000.yaml', 'http/cves/2024/CVE-2024-20419.yaml', 'javascript/cves/2024/CVE-2024-47176.yaml', 'http/cves/2024/CVE-2024-27564.yaml', 'http/cves/2024/CVE-2024-34351.yaml', 'http/cves/2024/CVE-2024-38472.yaml'], "Nuclei CVE Scans"),
            (['nuclei', '-u', args.domain], "Nuclei Default Templates"),
        ]

        for command, description in nuclei_commands:
            stdout, stderr = run_command_with_timeout(command, timeout=30)  # Set timeout to 30 seconds
            print(f"Running: {' '.join(command)}")  # Print the command being run
            print(f"Output: {stdout}")  # Print the output
            print(f"Error: {stderr}")  # Print any errors
            results.append([description, stdout if stdout else "Error", stderr if stderr else ""])
        print("")
        print("====Scan Result====")
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
