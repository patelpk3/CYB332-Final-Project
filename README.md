CYB-332 Multi-Agent LLM Penetration Testing Tool
A multi-agent LLM-powered penetration testing pipeline built with LangChain and Anthropic's Claude. The system automates reconnaissance, vulnerability analysis, and report generation against a controlled target environment.


Team Members
Carlito Otero
 Parth Patel
Baylen Romanello
Alex Patneaude
JT Depke


Architecture Overview
main.py  (user interface)

    └── Orchestrator Agent

            ├── validates target scope

            ├── plans task sequence using LLM

            ├── dispatches agents

            └── aggregates final output

                    ├── Recon Agent

                    │       ├── nmap_tool.py   (port scanning)

                    │       ├── whois_tool.py  (domain lookup)

                    │       └── hping3_tool.py (packet probing)

                    ├── Vulnerability Analyst Agent

                    │       └── reasons over recon findings using LLM

                    └── Report Writer Agent

                            └── generates structured pen-test report


Requirements
System Dependencies
These must be installed on your machine before running the project.

Mac (Homebrew):

brew install nmap whois hping3

Linux (Ubuntu/Debian):

sudo apt-get install nmap whois hping3
Python
Python 3.10 or higher required
Check your version: python3 --version
Target Environment
You need a vulnerable target to scan. We are using two main options:

Option A — Docker (Recommended, most portable):

Install Docker Desktop from https://docker.com/products/docker-desktop
Run Metasploitable 2 in Docker (see Target Setup section below)

Option B — QEMU VM:

Install QEMU: brew install qemu
Download Metasploitable 2 from https://sourceforge.net/projects/metasploitable/
Convert and run (see Target Setup section below)


Installation
Step 1 — Clone the repository
git clone https://github.com/patelpk3/CYB332-Final-Project

cd CYB332-Final-Project
Step 2 — Create and activate virtual environment
python3 -m venv venv

source venv/bin/activate

Every time you open a new terminal to work on this project, run source venv/bin/activate first.
Step 3 — Install Python dependencies
Important: The requirements file is named requirements (no .txt extension). Use the exact command below:

pip install -r requirements
Step 4 — Set up your API key
Create a file named .enviro_key in the root of the project:

ANTHROPIC_API_KEY=your_api_key_here

Get your API key from https://console.anthropic.com

Never push this file to GitHub. It is already listed in .gitignore.


Target Setup
Option A — Docker (Recommended)
Make sure Docker Desktop is running, then:

docker run -d \

  -p 21:21 \

  -p 22:22 \

  -p 23:23 \

  -p 25:25 \

  -p 8080:80 \

  -p 139:139 \

  -p 445:445 \

  -p 1524:1524 \

  -p 2121:2121 \

  -p 13306:3306 \

  -p 5432:5432 \

  -p 5900:5900 \

  -p 6667:6667 \

  -p 8180:8180 \

  --name metasploitable tleemcjr/metasploitable2

Your target IP will be: 127.0.0.1

To stop the container:

docker stop metasploitable

To restart it later:

docker start metasploitable
Option B — QEMU VM
# Install QEMU

brew install qemu

# Download Metasploitable 2 from SourceForge and unzip it

# Then convert the .vmdk file

qemu-img convert -f vmdk ~/Desktop/Metasploitable2-Linux/Metasploitable.vmdk -O qcow2 ~/Desktop/Metasploitable.qcow2

# Run the VM

qemu-system-x86_64 \

  -m 512 \

  -hda ~/Desktop/Metasploitable.qcow2 \

  -netdev user,id=net0 \

  -device e1000,netdev=net0 \

  -display default

Login credentials: msfadmin / msfadmin

Note: QEMU uses NAT networking by default. For direct scanning access, use the Docker option instead.


Running the Tool
Make sure your virtual environment is activated and your target is running, then:

python3 main.py

You will see a menu with three options:

=== Penetration Testing Menu ===

1. Full Orchestration (All Agents)

2. Reconnaissance Only

3. Check If Target In Scope

0. Exit

Enter a target IP or domain when prompted:

Docker target: 127.0.0.1
Public test target: scanme.nmap.org

The tool runs through all four agents and saves the final report to report_output.json. All LLM calls and tool outputs are logged to pentest_log.txt.


Project Structure
CYB332-Final-Project/

├── main.py                  # Entry point and user interface

├── state.py                 # Shared JSON state schema

├── requirements             # Python dependencies (no .txt extension)

├── .gitignore

├── README.md

├── agents/

│   ├── __init__.py

│   ├── orchestrator.py      # Agent 1 - coordinates pipeline

│   ├── recon.py             # Agent 2 - runs nmap, whois, hping3

│   ├── vul_anal.py          # Agent 3 - vulnerability analysis

│   └── report_writer.py     # Agent 4 - generates final report

└── tools/

    ├── __init__.py

    ├── nmap_tool.py         # nmap wrapper using python-nmap

    ├── whois_tool.py        # whois wrapper using python-whois

    └── hping3_tool.py       # hping3 wrapper for packet probing


Allowed Scope
The orchestrator enforces a strict scope. The tool will refuse to scan any target outside this list:

SCOPE = ["127.0.0.1", "scanme.nmap.org", "testphp.vulnweb.com", "172.17.0.2", "10.0.2.15"]

Attempting to scan an out-of-scope target will halt execution immediately. This hardcoding of the scope allows for a practical security trade off, however, the scope can be altered for use


Dependencies
Package
Purpose
langchain
Agent framework
langchain-anthropic
Anthropic/Claude integration
anthropic
Anthropic API client
python-nmap
nmap Python wrapper
python-whois
whois wrapper
python-dotenv
loads API key from .enviro_key



Logging
Every run generates two output files:

report_output.json — the final structured pen-test report (overwritten each run)
LLM_log.txt — appended log of all LLM calls, tool outputs, and agent findings

Both files are listed in .gitignore and will not be pushed to GitHub.


Ethical Notice
This tool is designed exclusively for use against the provided lab environment (Metasploitable 2). Running this tool against any system you do not own or have explicit written permission to test is against the tools intended purpose. All testing must be performed within the controlled virtual lab environment only.


Common Troubleshooting 
externally-managed-environment error when installing packages: Make sure you have activated the virtual environment first:

source venv/bin/activate

command not found: nmap:

brew install nmap

hping3 is not installed or not in PATH:

brew install hping3

Docker daemon not running: Open Docker Desktop from your Applications folder and wait for the whale icon to appear in your menu bar.

API key not found error: Make sure your .enviro_key file exists in the project root and contains:

ANTHROPIC_API_KEY=your_key_here

nmap scan returns no hosts:

Make sure your target VM/container is running
For Docker: confirm container is running with docker ps
For QEMU: use Docker option instead for better network compatibility
Try running nmap -sV 127.0.0.1 directly in terminal to verify connectivity

