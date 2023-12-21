# VirusTotal_CTI_IP
Fetching required IP details from virusTotal and CTI Threatbook.
# IP Reputation Checker

This script checks the reputation of IP addresses using VirusTotal and CTI_ThreatBook APIs.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Overview

The script processes a list of IP addresses stored in an Excel file and fetches their reputation information using VirusTotal and CTI_ThreatBook APIs. The results are saved in an output Excel file, providing details such as malicious count, ASN owner, country information, judgment values, and final verdict.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/your-repo.git
```

2. Install the required packages:

```bash
pip install -r requirements.txt
```

3. Obtain API keys:

- [VirusTotal API Key](https://developers.virustotal.com/reference#public-vs-private-api): Replace `'YOUR_VT_API_KEY'` in the script with your VirusTotal API key.
- [CTI_ThreatBook API Key](https://api.threatbook.io/docs/en/key): Replace `'YOUR_CTI_API_KEY'` in the script with your CTI_ThreatBook API key.

## Usage

1. Place the input file (`input.xlsx`) containing the list of IP addresses in the project directory.

2. Run the script:

```bash
python main_script.py
```

3. Results will be saved in the "Result" folder in an output Excel file (`output_datetime.xlsx`).

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
