# 🔍 Mass IP Reputation Checker

A Python command-line tool that extracts IP addresses from log files and checks their reputation using the [AlienVault OTX](https://otx.alienvault.com/) API.

## What It Does

- Extracts IP addresses from `.txt`, `.json`, or `.csv` files (or manual paste)
- Checks each IP against AlienVault OTX threat intelligence
- Classifies IPs as **Clean**, **Suspicious**, or **Malicious**
- Exports results to CSV or Excel

## Usage

```bash
# Check IPs from a file
python checker.py -f sample_logs.txt -k YOUR_API_KEY

# Export results to CSV
python checker.py -f sample_logs.txt -k YOUR_API_KEY -o csv

# Manual paste mode (no file)
python checker.py -k YOUR_API_KEY
```

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
pip install -r requirements.txt
```

## Get an API Key

1. Sign up at [AlienVault OTX](https://otx.alienvault.com/)
2. Go to your profile → API Key
3. Pass it with `-k YOUR_KEY` (never hardcode it!)
