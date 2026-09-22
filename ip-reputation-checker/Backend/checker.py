import re
import requests
import pandas as pd
import argparse
import json
import csv
import os
import ipaddress

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"



def parse_args():
    parser = argparse.ArgumentParser(
        description="Mass IP Reputation Checker - checks IPs against AlienVault OTX"
    )
    parser.add_argument(
        "-f", "--file",
        help="Path to input file (.txt, .json, .csv)",
        required=False
    )
    parser.add_argument(
        "-k", "--key",
        help="Your AlienVault OTX API key",
        default=os.getenv("OTX_API_KEY")
    )
    parser.add_argument(
        "-o", "--output",
        help="Export format: csv or excel",
        choices=["csv", "excel"],
        required=False
    )
    return parser.parse_args()



def read_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()

    allowed = [".txt", ".json", ".csv"]
    if ext not in allowed:
        print(f"Error: file type '{ext}' not allowed. Use .txt .json or .csv")
        exit()

    if ext == ".txt":
        with open(filepath, "r") as f:
            return f.read()

    elif ext == ".json":
        with open(filepath, "r") as f:
            data = json.load(f)

        return json.dumps(data)

    elif ext == ".csv":
        with open(filepath, "r") as f:
            reader = csv.reader(f)
            rows = [" ".join(row) for row in reader]

        return "\n".join(rows)



def get_manual_input():
    print("\nNo file provided. Paste your log text below.")
    print("Type END on a new line when done:\n")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)



def extract_ips(text):
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    matches = re.findall(pattern, text)
    unique_ips = []
    for ip in matches:
        try:
            if ipaddress.ip_address(ip).version == 4 and ip not in unique_ips:
                unique_ips.append(ip)
        except ValueError:
            continue
    return unique_ips



def fetch_ip_data(ip, api_key):
    url = OTX_URL.format(ip)
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=8)
        return response.json()
    except Exception:
        return None



def classify_ip(data):
    if data is None:
        return "Error", "-", "Unknown"

    pulse_count = data.get("pulse_info", {}).get("count", 0)
    country = data.get("country_name", "Unknown")

    if pulse_count >= 5:
        status = "Malicious"
    elif pulse_count >= 1:
        status = "Suspicious"
    else:
        status = "Clean"

    return status, pulse_count, country



def print_result(ip, status, pulse_count, country):
    label = {
        "Malicious":  "[MALICIOUS]",
        "Suspicious": "[SUSPICIOUS]",
        "Clean":      "[CLEAN]",
    }.get(status, "[ERROR]")

    print(f"  {label:15} {ip:20} Pulses: {str(pulse_count):5} Country: {country}")



def export_results(results, format):
    df = pd.DataFrame(results)

    if format == "csv":
        df.to_csv("ip_results.csv", index=False)
        print("\n Results saved to ip_results.csv")

    elif format == "excel":
        df.to_excel("ip_results.xlsx", index=False)
        print("\n Results saved to ip_results.xlsx")



if __name__ == "__main__":
    args = parse_args()

    if not args.key:
        raise SystemExit(
            "Missing API key. Set OTX_API_KEY or pass it with --key."
        )

    print("=" * 55)
    print("      MASS IP REPUTATION CHECKER")
    print("=" * 55)


    if args.file:
        print(f"\n Reading file: {args.file}")
        text = read_file(args.file)
    else:
        text = get_manual_input()


    ips = extract_ips(text)

    if not ips:
        print("\n No IP addresses found.")
        exit()

    print(f"\n Found {len(ips)} unique IP(s). Checking reputation...\n")
    print("-" * 65)
    print(f"  {'STATUS':15} {'IP ADDRESS':20} {'PULSES':11} {'COUNTRY'}")
    print("-" * 65)

    results = []
    clean_count = suspicious_count = malicious_count = error_count = 0

    for ip in ips:
        data = fetch_ip_data(ip, args.key)
        status, pulse_count, country = classify_ip(data)
        print_result(ip, status, pulse_count, country)

        results.append({
            "IP Address":  ip,
            "Status":      status,
            "Pulse Count": pulse_count,
            "Country":     country,
        })

        if status == "Clean":         clean_count += 1
        elif status == "Suspicious":  suspicious_count += 1
        elif status == "Malicious":   malicious_count += 1
        else:                         error_count += 1

    print("-" * 65)
    print(f"\n  SUMMARY")
    print(f"  Total IPs scanned : {len(ips)}")
    print(f"  Clean             : {clean_count}")
    print(f"  Suspicious        : {suspicious_count}")
    print(f"  Malicious         : {malicious_count}")
    if error_count > 0:
        print(f"  Errors            : {error_count}")
    print()


    if args.output:
        export_results(results, args.output)