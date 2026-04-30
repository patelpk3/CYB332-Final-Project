import subprocess
import shutil
import json
import re


def run_hping3(target: str, port: int = 80, count: int = 3) -> dict:
    print(f"hping3 probing target: {target} on port {port}")

    try:
        port = int(port)
        count = int(count)

        if port < 1 or port > 65535:
            return {
                "tool": "hping3",
                "target": target,
                "status": "error",
                "error": "Port must be between 1 and 65535"
            }

        if count < 1:
            count = 1

        if count > 5:
            count = 5

        if shutil.which("hping3") is None:
            return {
                "tool": "hping3",
                "target": target,
                "port": port,
                "status": "error",
                "error": "hping3 is not installed or not in PATH"
            }

        command = [
            "hping3",
            "-S",
            "-p",
            str(port),
            "-c",
            str(count),
            target
        ]

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20
        )

        output = completed.stdout + completed.stderr

        transmitted = None
        received = None

        packet_match = re.search(
            r"(\d+)\s+packets transmitted,\s+(\d+)\s+packets received",
            output
        )

        if packet_match:
            transmitted = int(packet_match.group(1))
            received = int(packet_match.group(2))

        if "flags=SA" in output:
            response_summary = "Target responded with SYN-ACK. The selected port appears open."
        elif "flags=RA" in output:
            response_summary = "Target responded with RST-ACK. The host is reachable, but the selected port appears closed."
        elif received and received > 0:
            response_summary = "Target responded to the probe."
        else:
            response_summary = "No response detected. The host may be down, filtered, or blocking probes."

        return {
            "tool": "hping3",
            "target": target,
            "port": port,
            "probe_type": "tcp_syn",
            "count": count,
            "status": "success",
            "packets_transmitted": transmitted,
            "packets_received": received,
            "response_summary": response_summary,
            "raw_output": output[-4000:]
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": "hping3",
            "target": target,
            "port": port,
            "status": "error",
            "error": "hping3 command timed out"
        }

    except Exception as err:
        return {
            "tool": "hping3",
            "target": target,
            "port": port,
            "status": "error",
            "error": str(err)
        }


if __name__ == "__main__":
    result = run_hping3("127.0.0.1", port=80, count=3)
    print(json.dumps(result, indent=2))