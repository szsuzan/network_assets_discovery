# Build an L2-capable scanner agent image for Linux hosts.
#
# Run it with host networking + raw-socket capability so ARP and SYN scans work
# against the host's actual LAN (nmap needs root for ARP/SYN):
#
#   docker build -t scanner-agent -f agent/Dockerfile .
#   docker run -d --network=host --name scanner-agent \
#     --cap-add NET_RAW --cap-add NET_ADMIN \
#     -e SCANNER_AGENT_KEY=<key> \
#     scanner-agent --server http://<server-host>:8000 --name host-linux
#
FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap iproute2 arping \
 && rm -rf /var/lib/apt/lists/*

COPY agent/scanner_agent.py /opt/scanner_agent.py

ENTRYPOINT ["python", "/opt/scanner_agent.py"]
CMD ["--help"]