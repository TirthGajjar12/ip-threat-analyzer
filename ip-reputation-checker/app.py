from flask import Flask,render_template,request
from checker import extract_ips,fetch_ip_data,classify_ip

app = Flask(__name__)

@app.route("/",methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan",methods=["POST"])
def scan():
    text = request.form.get("text","")
    api_key = request.form.get("api_key","")

    if not text.strip():
        return render_template("index.html",error="please paste some log text")

    if not api_key.strip():
        return render_template("index.html",error="please paste your api key")

    ips = extract_ips(text)

    if not ips:
        return render_template("index.html",error="No ips found in this pasted text")

    results = []
    clean = suspicious = malicious = 0

    for ip in ips:
        data = fetch_ip_data(ip,api_key)
        result = classify_ip(data)

        results.append({
            "ip":          ip,
            "status":      result["status"],
            "pulse_count": result["pulse_count"],
            "country":     result["country"],
            "tags":        result["tags"],
            "malware":     result["malware"],
            "adversary":   result["adversary"],
            "pulse_names": result["pulse_names"],
        })


        if result["status"] == "Clean":        clean += 1
        elif result["status"] == "Suspicious": suspicious += 1
        elif result["status"] == "Malicious":  malicious += 1

    return render_template("results.html",
        results    = results,
        total      = len(results),
        clean      = clean,
        suspicious = suspicious,
        malicious  = malicious,
        )


if __name__ == "__main__":
    app.run(debug=True)