<a href='https://postimg.cc/HjZWXWkt' target='_blank'><img src='https://i.postimg.cc/HjZWXWkt/WProject.png' border='0' alt='WProject'/></a>
# About

WProject is a Web Vulnerability Scanner. This tool is designed for security professionals and penetration testers to perform comprehensive vulnerability scanning on web applications. It uses various external open-source vulnerability tools.

## Main Features

   - Subdomain enumeration
   - Whois Lookup
   - Technology detection
   - Web crawling and URL extraction
   - Favicon hash calculation
   - 403 Forbidden bypass attempts
   - Local File Inclusion (LFI) scanning with Nuclei
   - Directory Traversal
   - Web Server Detection
   - JavaScript file scanning for sensitive info
   - Good Scan Report
   - Web GUI
   - Save Scan Result to File

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
usage: wproject.py [-h] -u DOMAIN [--auto] [--random-agent] [--fbypass] [--cleanup] [--gui]

Automated scanning tool.

options:
  -h, --help            show this help message and exit
  -u                    The domain to scan
  --auto                Run automated scans
  --random-agent        Use a random user agent for requests
  --fbypass             Bypass 403
  --cleanup             Delete previous Scan Reports
  --gui                 Start an Interactive Web GUI
```
