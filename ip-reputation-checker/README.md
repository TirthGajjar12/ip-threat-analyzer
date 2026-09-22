# 🔍 Mass IP Reputation Checker

A Python command-line tool that extracts IP addresses from log files and checks their reputation using the [AlienVault OTX](https://otx.alienvault.com/) API.

## What It Does

- Extracts IP addresses from `.txt`, `.json`, or `.csv` files (or manual paste)
- Checks each IP against AlienVault OTX threat intelligence
- Classifies IPs as **Clean**, **Suspicious**, or **Malicious**
- Exports results to CSV or Excel

## Usage

Set the API key in your environment so it is not stored in shell history:

```powershell
$env:OTX_API_KEY = "YOUR_API_KEY"
```

```bash
# Check IPs from a file
python Backend/checker.py -f sample_logs.txt

# Export results to CSV
python Backend/checker.py -f sample_logs.txt -o csv

# Manual paste mode (no file)
python Backend/checker.py
```

You can also pass the key explicitly with `--key`, but environment variables are safer for local use.

## Python Concepts Used

This project was built step-by-step to learn:

| Step | Concept |
|------|---------|
| 1 | Project setup, Git |
| 2 | Regex (`re` module) |
| 3 | File I/O |
| 4 | JSON & CSV parsing |
| 5 | User input handling |
| 6 | HTTP requests & APIs |
| 7 | Conditional logic |
| 8 | Data aggregation |
| 9 | Pandas & data export |
| 10 | argparse CLI |

## Setup

```bash
pip install -r Backend/requirements.txt
```

## Get an API Key

1. Sign up at [AlienVault OTX](https://otx.alienvault.com/)
2. Go to your profile → API Key
3. Pass it with `-k YOUR_KEY` (never hardcode it!)
