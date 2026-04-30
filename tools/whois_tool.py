import whois
import json

def run_whois(target: str) -> dict:
    """
    Runs the tool whois lookup on the target and returns the results.
    """
    print(f"Whois currently Looking up: {target}")
    
    try:
        w = whois.whois(target)
        
        return {
            "tool": "whois",
            "target": target,
            "status": "success",
            "parsed_fields": {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "country": w.country,
                "organization": w.org
            }
        }
    
    except Exception as err:
        return {
            "tool": "whois",
            "target": target,
            "status": "error",
            "error": str(err)
        }


if __name__ == "__main__":
    result = run_whois("127.0.0.1")
    print(json.dumps(result, indent=2))