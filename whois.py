import socket
import sys
from tabulate import tabulate

# Fields to be displayed in the final output
RELEVANT_FIELDS = [
    "Domain Name",
    "Registry Domain ID",
    "Registrar WHOIS Server",
    "Registrar URL",
    "Updated Date",
    "Creation Date",
    "Registry Expiry Date",
    "Registrar",
    "Registrar IANA ID",
    "Registrar Abuse Contact Email",
    "Registrar Abuse Contact Phone",
    "Domain Status",
    "Name Server",
    "DNSSEC",
]

def sanitize_domain(domain):
    # Remove 'http://' or 'https://' if it exists
    if domain.startswith('http://'):
        domain = domain[7:]
    elif domain.startswith('https://'):
        domain = domain[8:]

    # Remove any trailing slash or path if present
    domain = domain.split('/')[0]
    
    return domain

def whois_lookup(domain):
    # WHOIS server for .com domains
    whois_server = "whois.verisign-grs.com"
    
    # Create a socket connection to the WHOIS server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((whois_server, 43))  # Port 43 is the WHOIS port
        s.send((domain + "\r\n").encode())
        
        # Receive the response from the server
        response = ""
        while True:
            data = s.recv(4096).decode()
            if not data:
                break
            response += data

    return response

def parse_whois_response(response):
    # Create a dictionary to store parsed data
    parsed_data = []
    
    # Split the response line by line
    for line in response.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            key, value = key.strip(), value.strip()
            if key in RELEVANT_FIELDS:
                parsed_data.append([key, value])
    
    return parsed_data

def main():
    if len(sys.argv) != 3 or sys.argv[1] != '-u':
        print("Usage: python whois_lookup.py -u {DOMAIN}")
        sys.exit(1)

    # Sanitize the domain to remove https/http and any extra path
    domain = sanitize_domain(sys.argv[2])
    
    # Perform the WHOIS lookup
    result = whois_lookup(domain)
    
    # Parse the WHOIS response into key-value pairs and filter the relevant fields
    parsed_data = parse_whois_response(result)
    
    # Display the result in a table format using tabulate
    if parsed_data:
        print(tabulate(parsed_data, headers=["Field", "Value"], tablefmt="grid"))
    else:
        print("No WHOIS information found.")

if __name__ == "__main__":
    main()
