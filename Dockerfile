FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iproute2 nbtscan ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir zeroconf==0.147.2
WORKDIR /app
COPY src/recon.py /app/recon.py
RUN chmod 750 /app/recon.py && mkdir -p /output
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/python3", "/app/recon.py"]
