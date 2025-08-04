import requests

def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()
        if data['status'] == 'success':
            city = data.get("city", "")
            country = data.get("country", "")
            if city and country:
                return f"{city}, {country}"
            elif country:
                return country
        return "Unknown"
    except Exception:
        return "Unknown"
