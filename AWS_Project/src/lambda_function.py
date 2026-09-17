import json
import urllib.request
import gzip
import base64

# Replace these values with your actual credentials guysss
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
WEBHOOK_URL = "YOUR_DISCORD_OR_SLACK_WEBHOOK_URL"

def check_ip_reputation(ip):
    """Query AbuseIPDB API v2 using standard urllib (no external packages needed)."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("Key", ABUSEIPDB_API_KEY)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode()).get("data", {})
    except Exception as e:
        print(f"AbuseIPDB API Exception: {e}")
        return None

def send_alert(ip_data):
    """Send formatted alert payload to Discord/Slack Webhook."""
    ip = ip_data.get("ipAddress", "Unknown")
    score = ip_data.get("abuseConfidenceScore", 0)
    country = ip_data.get("countryCode", "N/A")
    usage_type = ip_data.get("usageType", "Unknown")

    payload = {
        "embeds": [{
            "title": "🚨🚨🚨 Automated SOAR Alert: Failed SSH Login Detected.Someone tryin' to break in🚨🚨🚨",
            "color": 15158332,
            "fields": [
                {"name": "Attacker IP", "value": f"`{ip}`", "inline": True},
                {"name": "Threat Score", "value": f"**{score}%**", "inline": True},
                {"name": "Country", "value": str(country), "inline": True},
                {"name": "Usage Type", "value": str(usage_type), "inline": True}
            ],
            "footer": {"text": "AWS Lambda Automated Threat Response"}
        }]
    }

    req = urllib.request.Request(
        WEBHOOK_URL, 
        data=json.dumps(payload).encode('utf-8'), 
        headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
    )
    try:
        with urllib.request.urlopen(req) as response:
            print(f"Webhook response status: {response.status}")
    except Exception as e:
        print(f"Webhook Exception: {e}")

def lambda_handler(event, context):
    """Decompress CloudWatch log payload and extract IP address."""
    print("Lambda triggered! Event payload received.")
    
    try:
        cw_data = event['awslogs']['data']
        compressed_payload = base64.b64decode(cw_data)
        uncompressed_payload = gzip.decompress(compressed_payload)
        log_data = json.loads(uncompressed_payload)
    except Exception as e:
        print(f"Payload Decompression Error: {e}")
        return {"statusCode": 400, "body": "Invalid Payload"}

    for log_event in log_data.get('logEvents', []):
        log_message = log_event.get('message', '')
        print(f"Processing log line: {log_message}")

        # Extract IP address from log line
        words = log_message.split()
        for i, word in enumerate(words):
            if word == "from" and i + 1 < len(words):
                raw_ip = words[i + 1].strip()
                print(f"Extracted IP candidate: {raw_ip}")
                
                # Query AbuseIPDB threat intel
                threat_info = check_ip_reputation(raw_ip)
                if threat_info:
                    print(f"Threat info fetched successfully for {raw_ip}")
                    send_alert(threat_info)
                else:
                    # Fallback alert if AbuseIPDB lookup fails
                    send_alert({"ipAddress": raw_ip, "abuseConfidenceScore": "N/A"})

    return {"statusCode": 200, "body": "Success"}
