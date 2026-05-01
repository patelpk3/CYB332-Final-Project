from tools.nmap_tool import run_nmap
from tools.whois_tool import run_whois
from tools.hping3_tool import run_hping3


def run_recon(target: str) -> dict:
    # Orchestrates nmap, whois, and hping3 against the target and returns combined results
    print(f"\n Starting recon on: {target}")

    nmap_results = run_nmap(target)
    whois_results = run_whois(target)

    # Default to port 80; prefer the first open port discovered by nmap for a more useful probe
    hping_port = 80
    open_ports = nmap_results.get("open_ports", [])
    if open_ports:
        hping_port = open_ports[0].get("port", 80)

    hping3_results = run_hping3(target, port=hping_port, count=3)

    print(f"Recon complete.")

    return {
        "status": "success",
        "target": target,
        "nmap": nmap_results,
        "whois": whois_results,
        "hping3": hping3_results
    }