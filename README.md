# About

WProject is high-level web vulnerability scanner assessment tool. This tool is designed for security professionals and penetration testers to perform comprehensive vulnerability scanning and vulnerability assessment on web applications. It combines multiple scanning techniques and integrates various external tools to provide a wide range of information about the target.

## Main Features

1. It imports various libraries for web scanning, web scraping, and parallel processing.

2. It includes multiple scanning functions for different purposes:
   - Subdomain enumeration
   - Whois Lookup
   - Technology detection
   - Web crawling and URL extraction
   - Favicon hash calculation
   - 403 Forbidden bypass attempts
   - Directory and file brute-forcing
   - Local File Inclusion (LFI) scanning with Nuclei
   - Google dorking
   - Directory Traversal
   - Web Server Detection
   - JavaScript file scanning for sensitive info
   - Good Scan Report

3. It includes options to save results to files

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
- SWS-Recon-Tool (MIT License)       
- Spyhunt (No License)          

Made by x0root.
