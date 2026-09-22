#!/usr/bin/env python3
import csv
import ipaddress
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/output"))
FORCE_PREFIX = int(os.getenv("FORCE_PREFIX", "24"))
TOP_PORTS = int(os.getenv("TOP_PORTS", "200"))
TIMING = os.getenv("NMAP_TIMING", "T3")
TARGET_NETWORK = os.getenv("TARGET_NETWORK", "").strip()
EXCLUDE_IPS = [x.strip() for x in os.getenv("EXCLUDE_IPS", "").split(",") if x.strip()]


def run(cmd):
    print("Kör:", " ".join(cmd), flush=True)
    result = subprocess.run(cmd, text=True)
    if result.returncode != 0:
        raise RuntimeError("Kommandot misslyckades: " + " ".join(cmd))


def output(cmd):
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Kommandot misslyckades")
    return result.stdout.strip()


def default_interface():
    for line in output(["ip", "-4", "route", "show", "default"]).splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("Ingen standardroute hittades")


def interface_ip(interface):
    data = output(["ip", "-4", "-o", "addr", "show", "dev", interface, "scope", "global"])
    for line in data.splitlines():
        parts = line.split()
        if "inet" in parts:
            return parts[parts.index("inet") + 1].split("/")[0]
    raise RuntimeError(f"Ingen IPv4-adress hittades på {interface}")


def scan_network(local_ip):
    if TARGET_NETWORK:
        network = ipaddress.ip_network(TARGET_NETWORK, strict=False)
    else:
        network = ipaddress.ip_network(f"{local_ip}/{FORCE_PREFIX}", strict=False)
    if not network.is_private:
        raise RuntimeError("Av säkerhetsskäl tillåts endast privata RFC1918-nät")
    if network.num_addresses > 256:
        raise RuntimeError("Nät större än /24 tillåts inte i Recon v1")
    return network


def parse_discovery(xml_path):
    root = ET.parse(xml_path).getroot()
    devices = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = hostname = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4": ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        hn = host.find("./hostnames/hostname")
        if hn is not None: hostname = hn.get("name", "")
        if ip:
            devices[ip] = {"IP": ip, "Hostname": hostname, "MAC": mac, "Vendor": vendor,
                           "OS": "", "OpenPorts": "", "Services": "", "Status": "Up"}
    return devices


def enrich(devices, xml_path):
    root = ET.parse(xml_path).getroot()
    for host in root.findall("host"):
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4": ip = addr.get("addr", "")
        if not ip or ip not in devices: continue
        osmatch = host.find("./os/osmatch")
        if osmatch is not None: devices[ip]["OS"] = osmatch.get("name", "")
        ports, services = [], []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open": continue
            proto, number = port.get("protocol", ""), port.get("portid", "")
            ports.append(f"{number}/{proto}")
            svc = port.find("service")
            if svc is not None:
                text = " ".join(x for x in [svc.get("name", ""), svc.get("product", ""), svc.get("version", "")] if x)
                services.append(f"{number}/{proto} {text}".strip())
        devices[ip]["OpenPorts"] = " | ".join(ports)
        devices[ip]["Services"] = " | ".join(services)
    return devices


def write_csv(devices, path, timestamp, network):
    fields = ["ScanTime", "Network", "IP", "Hostname", "MAC", "Vendor", "OS", "OpenPorts", "Services", "Status"]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter=";")
        writer.writeheader()
        for ip in sorted(devices, key=ipaddress.ip_address):
            row = dict(devices[ip]); row["ScanTime"] = timestamp; row["Network"] = str(network)
            writer.writerow(row)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Containern måste köras som root med NET_RAW och NET_ADMIN")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    stamp_report = datetime.now().isoformat(timespec="seconds")
    interface = default_interface()
    local_ip = interface_ip(interface)
    network = scan_network(local_ip)
    print(f"Interface: {interface}\nLokal IP: {local_ip}\nMålnät: {network}", flush=True)

    discovery_xml = OUTPUT_DIR / f"discovery_{stamp_file}.xml"
    services_xml = OUTPUT_DIR / f"services_{stamp_file}.xml"
    services_txt = OUTPUT_DIR / f"services_{stamp_file}.txt"
    hosts_file = OUTPUT_DIR / f"hosts_{stamp_file}.txt"
    csv_file = OUTPUT_DIR / f"recon_{stamp_file}.csv"

    cmd = ["nmap", "-sn", "-PR", f"-{TIMING}", "--max-retries", "2", "-oX", str(discovery_xml)]
    if EXCLUDE_IPS: cmd += ["--exclude", ",".join(EXCLUDE_IPS)]
    cmd.append(str(network)); run(cmd)
    devices = parse_discovery(discovery_xml)
    if not devices:
        print("Inga aktiva enheter hittades")
        return
    hosts_file.write_text("\n".join(devices) + "\n", encoding="utf-8")

    run(["nmap", "-Pn", "-sS", "-sV", "--version-light", "--top-ports", str(TOP_PORTS),
         f"-{TIMING}", "--max-retries", "2", "--host-timeout", "5m", "-iL", str(hosts_file),
         "-oX", str(services_xml), "-oN", str(services_txt)])
    enrich(devices, services_xml)
    write_csv(devices, csv_file, stamp_report, network)
    shutil.copy2(csv_file, OUTPUT_DIR / "latest-recon.csv")
    shutil.copy2(discovery_xml, OUTPUT_DIR / "latest-discovery.xml")
    shutil.copy2(services_xml, OUTPUT_DIR / "latest-services.xml")
    print(f"Klart: {len(devices)} enheter. Rapport: {csv_file}")

if __name__ == "__main__":
    try: main()
    except Exception as exc:
        print(f"Fel: {exc}", file=sys.stderr)
        sys.exit(1)
