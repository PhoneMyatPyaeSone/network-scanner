# Simple Network Scanner

Hi! I'm Phone Myat Pyae Sone, and this is the final project for the first semester using the Rust programming language—a simple network scanner. This tool helps users scan IP addresses and ports, identify running services, and resolve domain names to IP addresses.

## Developed By 
**Phone Myat Pyae Sone - 67011642**
**La Min Maung - 67011615**

## Installation Guide
First, ensure that Rust is already installed on your computer. If not, visit the following link to install it:

> https://www.rust-lang.org/tools/install

1. Clone the repository

> git clone https://github.com/PhoneMyatPyaeSone/network-scanner.git

2. Go to project directory
> cd network-scanner

3. Run cargo
> cargo run


## Features

-   **Port Scanning**: Check if specific ports on an IP address are open or closed.
-   **Service Detection**: Identifies common services based on port numbers.
-   **DNS Lookup**: Resolve domain names to their IP addresses.
-	**Save Results**: Export scan results to a JSON file for future reference.
## Technology Stack

- **Iced**
- **Serde**
- **Tokio**
- **Trust DNS Resolver**

## Usage Instructions

Switch between tabs to use different functionalities. The Scan tab is for port scanning, the Tools tab for DNS lookups, and the Help tab for detailed instructions.

## Disclaimer

This tool is for educational purposes only. Use only on networks you own or have explicit permission to scan. Unauthorized scanning is prohibited and may be illegal in some areas.

**Version 1.0.0 (November 2024)**