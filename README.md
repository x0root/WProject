# About

WProject is high-level web vulnerability scanner assessment tool. This tool is designed for security professionals and penetration testers to perform comprehensive vulnerability scanning and vulnerability assessment on web applications. It combines multiple scanning techniques and integrates various external tools to provide a wide range of information about the target.

## Here's a high-level overview of its functionality

1. It imports various libraries for web scanning, web scraping, and parallel processing.

2. The script defines a colorful banner and sets up command-line argument parsing for different scanning options.

3. It includes multiple scanning functions for different purposes:
   - Subdomain enumeration
   - Technology detection
   - Web crawling and URL extraction
   - Favicon hash calculation
   - 403 Forbidden bypass attempts
   - Directory and file brute-forcing
   - Local File Inclusion (LFI) scanning with Nuclei
   - Google dorking
   - Directory Traversal
   - SQL Injection
   - XSS
   - Web Server Detection
   - JavaScript file scanning for sensitive info
   - Good Scan Report

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
go install github.com/hahwul/dalfox/v2@latest

```

# Usage

```python
       __  __  __     ___ _____
 (   //__)/__)/  )  /(_  / )/
 |/|//   / ( (__/(_/ /__(__(


V.10
Made by x0root
usage: main.py [-h] -u DOMAIN [--auto] [--random-agent] [--fbypass]

Automated scanning tool.

options:
  -h, --help            show this help message and exit
  -u                    The domain to scan
  --auto                Run automated scans
  --random-agent        Use a random user agent for requests
  --fbypass             Bypass 403
```

Credits:
- Subfinder (MIT License)             
- Https (MIT License)            
- Nuclei (MIT License)           
- identYwaf (MIT License)       
- Spyhunt (No License)          

Made by x0root.
