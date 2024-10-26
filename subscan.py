import os
import asyncio
import aiohttp
import tldextract
import random
import dns.resolver
from colorama import init, Fore

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

# Function to scan for subdomains
async def scan_subdomains(domain, extracted_domain):
    async with aiohttp.ClientSession() as session:
        crtsh_subdomains = await crtsh_certificates(session, extracted_domain)
        print(f"Subdomains for {G}{extracted_domain}{X}\n")
        for subdomain in crtsh_subdomains:
            print(subdomain)
        return crtsh_subdomains

# Function to fetch DNS records for a domain
async def dns_records(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS']
    dns_records = {}
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

# Fetch certificates from crt.sh
async def crtsh_certificates(session, domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()
            json_response = await response.json()
            return list(set(entry["common_name"] for entry in json_response if entry["common_name"].endswith(domain)))
    except Exception as e:
        print(f"Error fetching crt.sh data for {domain}: {e}")
        return []

async def main_async():
    clear_console()
    print(banner)

    domain = input("Please enter a domain: ")
    extracted_domain = tldextract.extract(domain).registered_domain

    # Handle subdomain scanning
    subdomain_scan_result = await scan_subdomains(domain, extracted_domain)
    subdomain_text = ', '.join(subdomain_scan_result) if subdomain_scan_result else "No data"
    print(f"\nSubdomains:\n{subdomain_text}")

    # Handle DNS record scanning
    dns_record_result = await dns_records(domain)
    dns_record_text = ', '.join(dns_record_result) if dns_record_result else "No data"
    print(f"\nRecords:\n{dns_record_text}")

    print(f"Scan {G}Complete!{X}")
    input(f"\nPress [{G}ENTER{X}] to exit...")

# Run the main function
if __name__ == "__main__":
    asyncio.run(main_async())
