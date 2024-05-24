import os
import nmap
import json
import shodan
import asyncio
import aiohttp
import tldextract
import backoff
import random
import socket
import whois
import requests
import dns.resolver
from colorama import init, Fore
from bs4 import BeautifulSoup

# Initialize colorama for colorful console output
init()

# Color shortcuts for easier formatting
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
P = Fore.MAGENTA
X = Fore.RESET

# Function to clear the console window
def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

# Your Shodan API key
SHODAN_API_KEY = 'shodan_api_key_here'

# Semaphore for limiting concurrent network requests
semaphore = asyncio.Semaphore(10)

# Clear console at the start of the script
clear_console()

# User agent strings for HTTP requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
]

# ASCII Art banner for the application
banner = f"""
    {G}  _____       _    {P}           _         _           {X}
    {G} / ____|     | |   {P}          |_|       |_|          {X}
    {G}| (___  _   _| |__ {P} _ __ ___  _ ___ ___ ___   _____ {X}
    {G} \___ \| | | |  _ \{P}|  _ ` _ \| / __/ __| \ \ / / _ \{X}
    {G} ____) | |_| | |_) {P}| | | | | | \__ \__ \ |\ V /  __/{X}
    {G}|_____/ \__,_|_.__/{P}|_| |_| |_|_|___/___/_| \_/ \___|{X}
    
                           Asynchronous Domain Scanner
                                    From {G}PortLords{X} w Love
"""

api = (SHODAN_API_KEY)

# Function to scan IPs and ports of a given domain
async def scan_ips_ports(domain):
    nm = nmap.PortScanner()
    ip_addresses = domain_to_ips(domain)

    for ip in ip_addresses:
        nm.scan(ip, '1-1024')

        for host in nm.all_hosts():
            if nm[host].state() == "up":
                print(f"\n{G}{host}{X}")
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in sorted(lport):
                        port_status = nm[host][proto][port]['state']
                        # Conditional color based on status
                        status_color = Fore.GREEN if port_status == 'open' else Fore.RED
                        print(f"{Fore.YELLOW}{port}{Fore.RESET}/{Fore.YELLOW}{proto}{Fore.RESET} : {status_color}{port_status}{Fore.RESET}")
                await vulnerabilities(ip)
            else:
                print(f"\n{R}{host}{X}")

# Function to scan for subdomains
async def scan_subdomains(domain, extracted_domain):
    ip_addresses = domain_to_ips(domain)
    async with aiohttp.ClientSession() as session:
        clear_console()
        shodan_tasks = [shodan_details(session, ip) for ip in ip_addresses]
        shodan_results = await asyncio.gather(*shodan_tasks)
        crtsh_subdomains = await crtsh_certificates(session, extracted_domain)
        flat_shodan_subdomains = [hostname for sublist in shodan_results for hostname in sublist]
        all_subdomains = set(flat_shodan_subdomains + crtsh_subdomains)
        print(f"Subdomains for {G}{extracted_domain}{X}\n")
        for subdomain in all_subdomains:
            print(subdomain)
        return all_subdomains

# Function to look for vulnerabilities associated with an IP
async def vulnerabilities(ip):
    try:
        search_url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={ip}&search_type=all&isCpeNameSearch=false"
        response = requests.get(search_url)
        response.raise_for_status()  # Check for HTTP errors
        soup = BeautifulSoup(response.content, 'html.parser')
        vulnerabilities_found = False
        for result_item in soup.select('.result-item'):
            vulnerability_id = result_item.find('h5', class_='result-heading').text.strip()
            vulnerability_description = result_item.find('p', class_='result-description').text.strip()
            print(f"{vulnerability_id}: {vulnerability_description}")
            vulnerabilities_found = True

        if vulnerabilities_found:
            print(f"{Y}Vulns{X}: {R}Found{X}\n")
        else:
            print(f"{Y}Vulns{X}: {G}None{X}\n")

    except Exception as e:
        print(f"Error fetching NVD data for {ip}: {e}")

# Function to fetch DNS records for a domain
async def dns_records(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS']
    dns_records = {}
    clear_console()
    print(f"DNS Records for {G}{domain}{X}\n")
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [answer.to_text() for answer in answers]
            dns_records[record_type] = records
            
            if records:
                print(f"{G}{record_type}{X} records:")
                for record in records:
                    print(f"  - {record}")
            else:
                print(f"No {Y}{record_type}{X} records found.")
        
        except dns.resolver.NoAnswer:
            print(f"No {Y}{record_type}{X} records found.")
        except dns.resolver.NXDOMAIN:
            print(f"Domain {domain} does not exist.")
            break
        except Exception as e:
            print(f"Error fetching {Y}{record_type}{X} records: {e}")
    
    return dns_records

# Function to perform WHOIS lookup
async def whois_lookup(domain):
    try:
        clear_console()
        domain_info = whois.whois(domain)
        print(f"\nWHOIS for {G}{domain}{X}\n")
        
        filtered_info = {
            "Domain": domain_info.get("domain_name"),
            "Registrar": domain_info.get("registrar"),
            "Server": domain_info.get("whois_server"),
            "Creation Date": domain_info.get("creation_date"),
            "Exp. Date": domain_info.get("expiration_date"),
            "Name Servers": domain_info.get("name_servers"),
            "Status": domain_info.get("status")
        }

        for key, value in filtered_info.items():
            if value:
                print(f"{key}: {G}{value}{X}")

    except Exception as e:
        print(f"Error performing WHOIS lookup: {e}")

# Asynchronous fetch with retry for robustness
async def fetch_with_retry(session, url, headers=None):
    async with session.get(url, headers=headers) as response:
        response.raise_for_status()
        return await response.json()

# Resolve domain to IP addresses
def domain_to_ips(domain):
    try:
        _, _, ip_addresses = socket.gethostbyname_ex(domain)
        return ip_addresses
    except socket.gaierror:
        print(f"Failed to resolve {domain}")
        return []

# Fetch details from Shodan for given IP
async def shodan_details(session, ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data['hostnames']
            else:
                response.raise_for_status()
    except Exception as e:
        print(f"Error retrieving data for {ip}: {e}")
        return []

# Fetch certificates from crt.sh
async def crtsh_certificates(session, domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        json_response = await fetch_with_retry(session, url, headers)
        return list(set(entry["common_name"] for entry in json_response if entry["common_name"].endswith(domain)))
    except Exception as e:
        print(f"Error fetching crt.sh data for {domain}: {e}")
        return []

# Full scanning function combining all individual scans
async def full_scan(domain, extracted_domain):
    clear_console()
    
    output = []

    # IP and Port Scanning
    ip_addresses = domain_to_ips(domain)
    ip_text = ', '.join(ip_addresses) if ip_addresses else "No data"


    output.append(f"\nIPs: {ip_text}")

    # Handle subdomain scanning
    subdomain_scan_result = await scan_subdomains(domain, extracted_domain)
    subdomain_text = ', '.join(subdomain_scan_result) if subdomain_scan_result else "No data"
    output.append(f"\nSubdomains:\n{subdomain_text}")

    # Handle DNS record scanning
    dns_record_result = await dns_records(domain)
    dns_record_text = ', '.join(dns_record_result) if dns_record_result else "No data"
    output.append(f"\nRecords:\n{dns_record_text}")

    # Handle WHOIS lookup
    whois_result = await whois_lookup(domain)
    whois_text = ', '.join(whois_result) if whois_result else "No data"
    output.append(f"\nWhois:\n{whois_text}")

    # Save to file (or other output)
    filename = f"results/{domain.replace('.', '_')}.txt"
    with open(filename, 'w') as file:
        file.write('\n'.join(output))

    clear_console()

    print(f"Scan {G}Complete!{X} Results saved to {G}{filename}{X}")

# Main function to run the script
async def main_async():
    while True:
        clear_console()
        print(banner)
        menu_options = {
            f"[{G}1{X}]": "IPs / Ports",
            f"[{G}2{X}]": "Subdomains",
            f"[{G}3{X}]": "DNS Records",
            f"[{G}4{X}]": "Whois Records",
            f"[{G}5{X}]": "Full Scan",            
            f"[{R}0{X}]": "Exit"
        }
        for key, value in menu_options.items():
            print(f"{key} {value}")

        choice = input("\nChoose: ")

        if choice == "0":
            print("\nUntil next time..")
            break

        domain = input("Please enter a domain: ")
        extracted_domain = tldextract.extract(domain).registered_domain

        if choice == "1":
            ip_addresses = domain_to_ips(domain)
            clear_console()
            print(f"IPs: {G}{ip_addresses}{X}\n\nPlease wait...")
            await scan_ips_ports(domain)

        elif choice == "2":
            await scan_subdomains(domain, extracted_domain)

        elif choice == "3":
            await dns_records(domain)

        elif choice == "4":
            await whois_lookup(domain)

        elif choice == "5":
            await full_scan(domain, extracted_domain)

        else:
            print(f"{R}Error{X}! Please choose a valid option.")

        input(f"\nPress [{G}ENTER{X}] to continue...")

# Run the main function
if __name__ == "__main__":
    asyncio.run(main_async())