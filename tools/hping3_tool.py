import subprocess
import shutil
import json
import re


def run_hping3(target: str, port: int = 80, count: int = 3) -> dict:
    # Sends TCP SYN probes to the target and interprets the response flags to assess port state
    print(f"hping3 probing target: {target} on port {port}")

    try:
        # Cast to int in case the caller passes strings (e.g., from JSON or CLI args)
        port = int(port)
        count = int(count)

        # Reject invalid port numbers before invoking the tool
        if port < 1 or port > 65535:
            return {
                "tool": "hping3",
                "target": target,
                "status": "error",
                "error": "Port must be between 1 and 65535"
            }

        # Clamp count to a safe range to avoid accidental long-running probes
        if count < 1:
            count = 1

        if count > 5:
            count = 5

        # Fail early if the tool is not available so the error is clear
        if shutil.which("hping3") is None:
            return {
                "tool": "hping3",
                "target": target,
                "port": port,
                "status": "error",
                "error": "hping3 is not installed or not in PATH"
            }

        # -S sends SYN packets, -p sets the destination port, -c sets the packet count
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
            timeout=20      # 20-second hard limit to prevent the probe from hanging indefinitely
        )

        # The tool writes some output to stderr, so combine both streams for parsing
        output = completed.stdout + completed.stderr

        transmitted = None
        received = None

        # Parse the summary line (e.g. "3 packets transmitted, 3 packets received")
        packet_match = re.search(
            r"(\d+)\s+packets transmitted,\s+(\d+)\s+packets received",
            output
        )

        if packet_match:
            transmitted = int(packet_match.group(1))
            received = int(packet_match.group(2))

        # Interpret TCP flag responses to determine port state
        # SYN-ACK (SA) means the port is open; RST-ACK (RA) means the port is closed but reachable
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
            # Truncate raw output to 4000 chars to keep the result payload reasonable
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
    # Quick standalone test — probe localhost port 80 with 3 SYN packets
    result = run_hping3("127.0.0.1", port=80, count=3)
    print(json.dumps(result, indent=2))
