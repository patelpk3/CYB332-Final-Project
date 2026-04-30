import nmap
import json

def run_nmap(target: str) -> dict:
    """
    Runs an nmap scan on the target and returns the results.
    """
    print(f"Nmap scanning the target: {target}")
    
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments="-sV -T4 --open")

        # Get actual host key, Nmap typically stores by IP
        #  We would rather have the hostname
        hosts = scanner.all_hosts()
        if not hosts:
            return {
                "tool used": "nmap",
                "target": target,
                "status": "error",
                "error": "No hosts found"
            }

        host = hosts[0]  # grab the actual IP
        open_ports = []
        for protocol in scanner[host].all_protocols():
            for port in scanner[host][protocol].keys():
                service = scanner[host][protocol][port]
                open_ports.append({
                    "port": port,
                    "protocol": protocol,
                    "state": service["state"],
                    "service": service["name"],
                    "version": service.get("version", "unknown")
                })

        return {
            "tool": "nmap",
            "target": target,
            "ip": host,
            "status": "success",
            "hostname": scanner[host].hostname(),
            "open_ports": open_ports
        }
    except Exception as err:
        return {
            "tool": "nmap",
            "target": target,
            "status": "error",
            "error": str(err)
        }

if __name__ == "__main__":
    result = run_nmap("127.0.0.1")
    print(json.dumps(result, indent=2))