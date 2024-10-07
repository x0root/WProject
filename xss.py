import argparse
import requests
import re

def read_xss_payloads(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        payloads = file.read().splitlines()
    return payloads

def change_user_agent(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        user_agent = file.read().strip()
    return user_agent

def extract_parameters(url):
    params = re.findall(r'[?&]([^=]+)=([^&]*)', url)
    return params

def inject_xss(url, payload):
    query_params = extract_parameters(url)
    for param, value in query_params:
        new_url = url.replace(f'{param}={value}', f'{param}={payload}')
        try:
            response = requests.get(new_url, headers={'User-Agent': change_user_agent('/host/agent.txt')})
            if 'alert' in response.text.lower() or 'prompt' in response.text.lower():
                return True, new_url
        except requests.RequestException as e:
            print(f"Error: {e}")
    return False, None

def scan_with_payloads(base_url, payloads):
    for payload in payloads:
        success, xss_url = inject_xss(base_url, payload)
        if success:
            print(f"Payload '{payload}' worked on URL: {xss_url}")

def main():
    parser = argparse.ArgumentParser(description='XSS Scanner')
    parser.add_argument('-u', '--url', required=True, help='The URL to test for XSS vulnerabilities')
    args = parser.parse_args()

    import os

    xss_payloads_path = os.path.join(os.path.dirname(__file__), 'payloads', 'xss.txt')  # Constructing the path dynamically
    xss_payloads = read_xss_payloads(xss_payloads_path)
    scan_with_payloads(args.url, xss_payloads)

if __name__ == "__main__":
    main()