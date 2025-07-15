#!/usr/bin/env python3
import argparse
import csv
import json
import time
from threading import Thread
from queue import Queue
from scapy.all import *

# Hedefi test eden worker fonksiyonu
def scan_worker(queue, results, scan_type):
    while not queue.empty():
        ip, port = queue.get()
        try:
            if scan_type == "tcp":
                is_open = scan_tcp_syn(ip, port)
            else:
                is_open = scan_udp(ip, port)
            results.append({"ip": ip, "port": port, "open": is_open, "protocol": scan_type})
        except Exception as e:
            results.append({"ip": ip, "port": port, "open": False, "protocol": scan_type, "error": str(e)})
        queue.task_done()

# TCP SYN Scan fonksiyonu
def scan_tcp_syn(ip, port):
    pkt = IP(dst=ip) / TCP(dport=port, sport=RandShort(), flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp is None:
        return False
    if resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            # Bağlantıyı kapatmak için RST gönder
            rst_pkt = IP(dst=ip) / TCP(dport=port, sport=pkt[TCP].sport, flags="R")
            send(rst_pkt, verbose=0)
            return True
        elif resp[TCP].flags == 0x14:  # RST-ACK
            return False
    return False

# UDP Scan fonksiyonu
def scan_udp(ip, port):
    pkt = IP(dst=ip) / UDP(dport=port)
    resp = sr1(pkt, timeout=2, verbose=0)
    if resp is None:
        return True  # Cevap yok, port açık ya da filtrelenmiş olabilir
    if resp.haslayer(ICMP):
        if resp[ICMP].type == 3 and resp[ICMP].code == 3:
            return False  # Port kapalı (ICMP unreachable)
        else:
            return True
    return True

# Sonuçları yazdırma fonksiyonu
def print_results(results):
    for r in results:
        status = "OPEN" if r["open"] else "CLOSED"
        print(f'{r["ip"]}:{r["port"]}/{r["protocol"].upper()} -> {status}')

# CSV olarak kaydet
def save_csv(results, filename):
    keys = ["ip", "port", "protocol", "open", "error"]
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

# JSON olarak kaydet
def save_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

# Düz metin olarak kaydet
def save_txt(results, filename):
    with open(filename, "w") as f:
        for r in results:
            status = "OPEN" if r["open"] else "CLOSED"
            line = f'{r["ip"]}:{r["port"]}/{r["protocol"].upper()} -> {status}\n'
            f.write(line)

def main():
    parser = argparse.ArgumentParser(description="Scapy TCP/UDP Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan, e.g. 22,80,443 or 1-1024")
    parser.add_argument("-st", "--scan-type", choices=["tcp", "udp"], default="tcp", help="Scan type (tcp or udp)")
    parser.add_argument("-o", "--output", choices=["txt", "csv", "json"], default="txt", help="Output format")
    parser.add_argument("-th", "--threads", type=int, default=100, help="Number of threads")
    args = parser.parse_args()

    # Hedef IP çözümle
    try:
        target_ip = socket.gethostbyname(args.target)
    except Exception as e:
        print(f"Invalid target: {e}")
        return

    # Port listesini oluştur
    ports = []
    for part in args.ports.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    q = Queue()
    results = []

    for port in ports:
        q.put((target_ip, port))

    threads = []
    for _ in range(min(args.threads, q.qsize())):
        t = Thread(target=scan_worker, args=(q, results, args.scan_type))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

    # Sonuçları yazdır ve kaydet
    print_results(results)

    filename = f"scan_results_{int(time.time())}.{args.output}"
    if args.output == "csv":
        save_csv(results, filename)
    elif args.output == "json":
        save_json(results, filename)
    else:
        save_txt(results, filename)

    print(f"Results saved to {filename}")

if __name__ == "__main__":
    main()
