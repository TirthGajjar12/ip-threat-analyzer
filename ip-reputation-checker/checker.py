import re
import requests

def extract_ips(text):
    pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    matches = re.findall(pattern,text)
    matches = list(dict.fromkeys(matches))
    return matches


def fetch_ip_data(ip, api_key):
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(otx_url, headers=headers, timeout=20)
        response.raise_for_status()
        return response.json()  # convert successful JSON response into Python data 
    except Exception as e:
        print("Error:",e)
        return None



# print(data)

def classify_ip(data):
    if data is None:
        return {
            "status": "Error",
            "pulse_count": "-",
            "country": "Unknown",
            "tags": "-",
            "malware": "-",
            "adversary": "-",
            "pulse_names": "-",
        }

    pulse_name = []
    all_tags = []
    all_adversaries = []
    all_malware = []


    pulse_info = data.get("pulse_info",{})
    pulse_count = pulse_info.get("count",0)
    pulses = pulse_info.get('pulses',[])
    country = data.get("country_name", "Unknown")

    # print(pulses)
    for pulse in pulses:
        name = pulse.get('name',"")
        if name:
            pulse_name.append(name)
        all_tags.extend(pulse.get("tags",[]))
        adversary =  pulse.get("adversary","")
        if adversary: 
            all_adversaries.append(adversary)
        for m in pulse.get("malware_families",[]):
            if isinstance(m,dict):
                all_malware.append(m.get("display_name",""))
            else:
                all_malware.append(str(m))

    pulse_name = list(dict.fromkeys(pulse_name))
    all_tags = list(dict.fromkeys(all_tags))
    all_adversaries = list(dict.fromkeys(all_adversaries))
    all_malware = list(dict.fromkeys(filter(None,all_malware)))

    if pulse_count >= 5:
        status = "Malicious"
    elif pulse_count >= 1:
        status = "Suspicious"
    else:
        status = "Clean"


    return {
        "status":status,
        "pulse_count" :pulse_count,
        "country": country,
        "pulse_names": ", ".join(pulse_name[:3]) if pulse_name else "None",
        "tags":        ", ".join(all_tags[:5])    if all_tags    else "None",
        "adversary":   ", ".join(all_adversaries) if all_adversaries else "Unknown",
        "malware":     ", ".join(all_malware)     if all_malware     else "None",
    }

# c = classify_ip()
# print(c)