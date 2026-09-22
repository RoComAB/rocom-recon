#!/usr/bin/env python3
import csv
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from zeroconf._exceptions import BadTypeInNameException
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/output"))
FORCE_PREFIX = int(os.getenv("FORCE_PREFIX", "24"))
TOP_PORTS = int(os.getenv("TOP_PORTS", "200"))
TIMING = os.getenv("NMAP_TIMING", "T3")
TARGET_NETWORK = os.getenv("TARGET_NETWORK", "").strip()
EXCLUDE_IPS = [x.strip() for x in os.getenv("EXCLUDE_IPS", "").split(",") if x.strip()]
MDNS_SECONDS = int(os.getenv("MDNS_SECONDS", "12"))
ENABLE_MDNS = os.getenv("ENABLE_MDNS", "true").lower() == "true"
ENABLE_NETBIOS = os.getenv("ENABLE_NETBIOS", "true").lower() == "true"


def run(cmd, capture=False, timeout=None):
    print("Kör:", " ".join(cmd), flush=True)
    result = subprocess.run(cmd, text=True, capture_output=capture, timeout=timeout)
    if result.returncode != 0:
        message = result.stderr.strip() if capture else ""
        raise RuntimeError(message or "Kommandot misslyckades: " + " ".join(cmd))
    return result.stdout.strip() if capture else ""


def default_interface():
    data = run(["ip", "-4", "route", "show", "default"], capture=True)
    for line in data.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("Ingen standardroute hittades")


def interface_ip(interface):
    data = run(["ip", "-4", "-o", "addr", "show", "dev", interface, "scope", "global"], capture=True)
    for line in data.splitlines():
        parts = line.split()
        if "inet" in parts:
            return parts[parts.index("inet") + 1].split("/")[0]
    raise RuntimeError(f"Ingen IPv4-adress hittades på {interface}")


def scan_network(local_ip):
    network = ipaddress.ip_network(TARGET_NETWORK, strict=False) if TARGET_NETWORK else ipaddress.ip_network(f"{local_ip}/{FORCE_PREFIX}", strict=False)
    if not network.is_private:
        raise RuntimeError("Av säkerhetsskäl tillåts endast privata RFC1918-nät")
    if network.num_addresses > 256:
        raise RuntimeError("Nät större än /24 tillåts inte i Recon Sprint 1")
    return network


def empty_device(ip):
    return {"IP": ip, "Hostname": "", "MAC": "", "Vendor": "", "DeviceType": "","RiskScore": 0, "OS": "", "OpenPorts": "",
            "Services": "", "mDNSNames": "", "mDNSServices": "", "NetBIOSName": "",
            "NetBIOSWorkgroup": "", "DiscoverySources": set(), "Status": "Up",}


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
            devices[ip] = empty_device(ip)
            devices[ip].update({"Hostname": hostname, "MAC": mac, "Vendor": vendor})
            devices[ip]["DiscoverySources"].add("ARP/Nmap")
    return devices


class MDNSCollector(ServiceListener):
    def __init__(self, network):
        self.network = network
        self.lock = threading.Lock()
        self.records = []

    def remove_service(self, zc, service_type, name):
        pass

    def update_service(self, zc, service_type, name):
        self.add_service(zc, service_type, name)

    def add_service(self, zc, service_type, name):
        try:
            info = zc.get_service_info(service_type, name, timeout=2000)
        except BadTypeInNameException:
            return
        except Exception:
            return
            
        if not info:
            return
        addresses = []
        for raw in info.addresses:
            try:
                ip = str(ipaddress.ip_address(raw))
                if ipaddress.ip_address(ip) in self.network:
                    addresses.append(ip)
            except ValueError:
                continue
        if not addresses:
            return
        server = (info.server or "").rstrip(".")
        properties = {}
        for key, value in info.properties.items():
            k = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
            v = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
            properties[k] = v
        with self.lock:
            for ip in addresses:
                self.records.append({"ip": ip, "name": name.rstrip("."), "type": service_type.rstrip("."),
                                     "server": server, "port": info.port, "properties": properties})


def discover_mdns(network):
    if not ENABLE_MDNS:
        return []
    print(f"Samlar mDNS/DNS-SD i {MDNS_SECONDS} sekunder", flush=True)
    zc = Zeroconf()
    collector = MDNSCollector(network)
    browser = ServiceBrowser(zc, "_services._dns-sd._udp.local.", collector)
    time.sleep(2)
    service_types = sorted({r["name"].replace("._services._dns-sd._udp.local", ".local.") for r in collector.records})
    browsers = [browser]
    for service_type in service_types:
        try:
            if not service_type.startswith("_"):
                continue

            browsers.append(
                ServiceBrowser(
                    zc,
                    service_type,
                    collector
                )
            )

        except Exception:
            continue
    
    time.sleep(max(1, MDNS_SECONDS - 2))
    zc.close()
    return collector.records


def merge_mdns(devices, records):
    grouped = {}
    for record in records:
        grouped.setdefault(record["ip"], []).append(record)
    for ip, items in grouped.items():
        devices.setdefault(ip, empty_device(ip))
        names, services = set(), set()
        for item in items:
            if item["server"]: names.add(item["server"])
            names.add(item["name"])
            services.add(f'{item["type"]}:{item["port"]}')
        devices[ip]["mDNSNames"] = " | ".join(sorted(names))
        devices[ip]["mDNSServices"] = " | ".join(sorted(services))
        if not devices[ip]["Hostname"] and names:
            devices[ip]["Hostname"] = sorted(names)[0]
        devices[ip]["DiscoverySources"].add("mDNS")


def discover_netbios(network):
    if not ENABLE_NETBIOS:
        return []
    print("Söker NetBIOS-namn", flush=True)
    try:
        data = run(["nbtscan", "-q", str(network)], capture=True, timeout=90)
    except Exception as exc:
        print(f"Varning: NetBIOS-sökningen misslyckades: {exc}", file=sys.stderr)
        return []
    records = []
    for line in data.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        records.append({"ip": parts[0], "name": parts[1], "workgroup": parts[2] if len(parts) > 2 else ""})
    return records


def merge_netbios(devices, records):
    for record in records:
        ip = record["ip"]
        devices.setdefault(ip, empty_device(ip))
        devices[ip]["NetBIOSName"] = record["name"]
        devices[ip]["NetBIOSWorkgroup"] = record["workgroup"]
        if not devices[ip]["Hostname"]:
            devices[ip]["Hostname"] = record["name"]
        devices[ip]["DiscoverySources"].add("NetBIOS")


def enrich_nmap(devices, xml_path):
    root = ET.parse(xml_path).getroot()
    for host in root.findall("host"):
        ip = next((a.get("addr", "") for a in host.findall("address") if a.get("addrtype") == "ipv4"), "")
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
        devices[ip]["DiscoverySources"].add("Nmap services")

def classify_device(device):

    vendor = device.get("Vendor", "").lower()
    services = device.get("Services", "").lower()

    device_type = "Unknown"

    if "clavister" in vendor:
        device_type = "Firewall"

    elif "meraki" in vendor:
        device_type = "Access Point"

    elif "avaya" in vendor:
        device_type = "Telephony"

    elif "hp" in vendor and (
        "ipp" in services or
        "printer" in services
    ):
        device_type = "Printer"

    elif "hewlett" in vendor:
        device_type = "Switch"

    elif (
        "microsoft" in services or
        "windows" in services
    ):
        device_type = "Workstation"

    risk = 0

    if "telnet" in services:
        risk += 50

    if "ftp" in services:
        risk += 30

    if "smb" in services:
        risk += 10

    if device_type == "Firewall":
        risk += 5

    device["DeviceType"] = device_type
    device["RiskScore"] = risk

def write_csv(devices, path, timestamp, network):
    fields = ["ScanTime", "Network", "IP", "Hostname", "MAC", "Vendor", "DeviceType", "RiskScore", "OS", "OpenPorts", "Services",
              "mDNSNames", "mDNSServices", "NetBIOSName", "NetBIOSWorkgroup", "DiscoverySources", "Status"]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter=";")
        writer.writeheader()
        for ip in sorted(devices, key=ipaddress.ip_address):
            row = dict(devices[ip])
            row["ScanTime"], row["Network"] = timestamp, str(network)
            row["DiscoverySources"] = " | ".join(sorted(row["DiscoverySources"]))
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
    mdns_csv = OUTPUT_DIR / f"mdns_{stamp_file}.csv"
    netbios_csv = OUTPUT_DIR / f"netbios_{stamp_file}.csv"
    csv_file = OUTPUT_DIR / f"recon_{stamp_file}.csv"

    cmd = ["nmap", "-sn", "-PR", f"-{TIMING}", "--max-retries", "2", "-oX", str(discovery_xml)]
    if EXCLUDE_IPS: cmd += ["--exclude", ",".join(EXCLUDE_IPS)]
    cmd.append(str(network)); run(cmd)
    devices = parse_discovery(discovery_xml)

    mdns_records = discover_mdns(network)
    merge_mdns(devices, mdns_records)
    with mdns_csv.open("w", newline="", encoding="utf-8-sig") as h:
        fields = ["ip", "name", "type", "server", "port", "properties"]
        w = csv.DictWriter(h, fieldnames=fields, delimiter=";"); w.writeheader(); w.writerows(mdns_records)

    netbios_records = discover_netbios(network)
    merge_netbios(devices, netbios_records)
    with netbios_csv.open("w", newline="", encoding="utf-8-sig") as h:
        fields = ["ip", "name", "workgroup"]
        w = csv.DictWriter(h, fieldnames=fields, delimiter=";"); w.writeheader(); w.writerows(netbios_records)

    if not devices:
        print("Inga aktiva enheter hittades")
        return
    hosts_file.write_text("\n".join(sorted(devices, key=ipaddress.ip_address)) + "\n", encoding="utf-8")
    run(["nmap", "-Pn", "-sS", "-sV", "--version-light", "--top-ports", str(TOP_PORTS),
         f"-{TIMING}", "--max-retries", "2", "--host-timeout", "5m", "-iL", str(hosts_file),
         "-oX", str(services_xml), "-oN", str(services_txt)])
    enrich_nmap(devices, services_xml)

    for device in devices.values():
        classify_device(device)
    
    write_csv(devices, csv_file, stamp_report, network)

    for source, latest in [(csv_file, "latest-recon.csv"), (discovery_xml, "latest-discovery.xml"),
                           (services_xml, "latest-services.xml"), (mdns_csv, "latest-mdns.csv"),
                           (netbios_csv, "latest-netbios.csv")]:
        shutil.copy2(source, OUTPUT_DIR / latest)
    print(f"Klart: {len(devices)} enheter, {len(mdns_records)} mDNS-poster, {len(netbios_records)} NetBIOS-poster")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        print("Avbruten", file=sys.stderr); sys.exit(130)
    except Exception as exc:
        print(f"Fel: {exc}", file=sys.stderr); sys.exit(1)
