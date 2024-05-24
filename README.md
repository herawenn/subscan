# Asynchronous Domain Scanner

This is an asynchronous domain scanner, designed to perform comprehensive scans including IP and port scanning, vulnerabilities, subdomain discovery, DNS record analysis, and WHOIS lookup. It is built using Python and utilizes various libraries to handle asynchronous tasks and network interactions efficiently.

![running the tool](https://i.imgur.com/XbFawRr.png)

## Features

- **IP and Port Scanning**: Scan and list all IPs and open ports for a given domain.
- **Subdomain Scanning**: Discover all subdomains associated with the main domain.
- **DNS Records Analysis**: Retrieve and display DNS records for the domain.
- **WHOIS Lookup**: Gather and present WHOIS information for the domain.

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/herawenn/subscan
   ```
2. Install requirements
   ```sh
   pip install -r requirements.txt
   ```
3. Run the program
   ```sh
   python subscan.py
   ```

## Configuration
Ensure you set up your Shodan API key in the script before running:

```bash
SHODAN_API_KEY = 'Your_Shodan_API_Key_Here'
```
Results of the full scan are saved in a text file, with detailed information about IPs, ports, subdomains, DNS records, and WHOIS data.

## License
This project is open-sourced under the MIT license. See the LICENSE file for more details.

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Disclaimer
This tool is for educational and ethical testing purposes only. Usage of this software for attacking targets without prior mutual consent is illegal. The developer will not be held responsible for any misuse or damage caused by this software.
