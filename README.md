# About

WProject is high-level web vulnerability scanner assessment tool. This tool is designed for security professionals and penetration testers to perform comprehensive reconnaissance and vulnerability assessment on target networks and web applications. It combines multiple scanning techniques and integrates various external tools to provide a wide range of information about the target.

## Here's a high-level overview of its functionality

1. It imports various libraries for web scanning, web scraping, and parallel processing.

2. The script defines a colorful banner and sets up command-line argument parsing for different scanning options.

3. It includes multiple scanning functions for different purposes:
   - Subdomain enumeration
   - Technology detection
   - DNS record scanning
   - Web crawling and URL extraction
   - Favicon hash calculation
   - Host header injection testing
   - Security header analysis
   - Network vulnerability analysis
   - Wayback machine URL retrieval
   - JavaScript file discovery
   - Broken link checking
   - HTTP request smuggling detection
   - IP address extraction
   - Domain information gathering
   - API endpoint fuzzing
   - Shodan integration for additional recon
   - 403 Forbidden bypass attempts
   - Directory and file brute-forcing
   - Local File Inclusion (LFI) scanning with Nuclei
   - Google dorking
   - Directory Traversal
   - SQL Injection
   - XSS
   - Web Server Detection
   - JavaScript file scanning for sensitive info
   - Good Scan Report using Table.

4. The script uses multithreading and multiprocessing to perform scans efficiently.

5. It includes options to save results to files and customize scan parameters.

6. It implements various techniques to bypass restrictions and discover vulnerabilities.

7. The script includes a CIDR notation scanner for port scanning across IP ranges.

# Install

```bash

git clone https://github.com/x0root/WProject.git
cd WProject
pip3 install -r requirements.txt
python3 install.py
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

```

Credits:
- Subfinder (MIT License)             
- Https (MIT License)                        
- Nuclei (MIT License)           
- identYwaf (MIT License)             
- Spyhunt (No License)          

Made by x0root.
