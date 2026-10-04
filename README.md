# IP Reputation Checker

A Flask web app that extracts IPv4 addresses from pasted log text and checks
them against AlienVault OTX threat intelligence. Results include a reputation
classification, pulse count, country, tags, malware, and adversary information.

## Requirements

- Python 3
- An [AlienVault OTX API key](https://otx.alienvault.com/)

## Run locally

From the repository root:

```powershell
cd ip-reputation-checker
python -m pip install -r requirements.txt
python app.py
```

Open the local address printed by Flask, paste log text and your OTX API key,
then submit it to view the results. The API key is entered in the form and is
not stored in the repository.

## Project files

- `ip-reputation-checker/app.py` - Flask application and scan route
- `ip-reputation-checker/checker.py` - IP extraction, OTX lookup, and classification
- `ip-reputation-checker/templates/` - HTML pages
- `ip-reputation-checker/static/` - stylesheet
