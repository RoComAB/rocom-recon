FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap iproute2 ca-certificates python3 tini \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/recon.py /app/recon.py
RUN chmod 750 /app/recon.py && mkdir -p /output
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/bin/python3", "/app/recon.py"]
