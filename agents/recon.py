from tools.nmap_tool import run_nmap
from tools.whois_tool import run_whois

def run_recon(target: str) -> dict:
    print(f"\n Starting recon on: {target}")

    nmap_results = run_nmap(target)
    whois_results = run_whois(target)

    print(f"Recon complete.")

    return {
        "status": "success",
        "target": target,
        "nmap": nmap_results,
        "whois": whois_results
    }
