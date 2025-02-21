#!/usr/bin/env python3
import argparse
import socket
import json
import csv
import os
import threading
import subprocess
from colorama import init, Fore

def activate_venv():
    print("Activating Virtual environment ...")
    subprocess.call([os.path.expanduser('~/alpha-psc-env/bin/activate')], shell=True)

    


init(autoreset=True)

def log_result(message):
    with open("scan.log", "a") as log_file:
        log_file.write(message + "\n")

def scan_port(ip, port, scan_type):
    try:
        if scan_type == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        elif scan_type == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            try:
                sock.sendto(b'', (ip, port))
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                return False
            finally:
                sock.close()
    except Exception as e:
        print(Fore.RED + f"Error scanning {ip}:{port} - {e}")
        return False

def save_result(target, port, output_format, file):
    if output_format == 'json':
        result = {"target": target, "port": port}
        file.write(json.dumps(result) + "\n")
    elif output_format == 'csv':
        writer = csv.writer(file)
        writer.writerow([target, port])
    elif output_format == 'txt':
        file.write(f"{target}:{port}\n")

def scan_target(target, ports, scan_type, output_format, output_file):
    with open(output_file, 'a', newline='') as f:
        if output_format == 'csv' and os.stat(output_file).st_size == 0:
            writer = csv.writer(f)
            writer.writerow(['Target', 'Port'])
        for port in ports:
            print(Fore.CYAN + f"Scanning {target}:{port}...")  
            if scan_port(target, port, scan_type):
                success_msg = f"[OPEN] {target}:{port}"
                print(Fore.GREEN + success_msg)  
                log_result(success_msg)  
                save_result(target, port, output_format, f)
            else:
                print(Fore.RED + f"[CLOSED] {target}:{port}")  

def thread_scan(targets, ports, scan_type, output_format, output_file):
    threads = []
    for target in targets:
        t = threading.Thread(target=scan_target, args=(target, ports, scan_type, output_format, output_file))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def main():

    activate_venv()

    parser = argparse.ArgumentParser(description="Alpha Port Scanner (alpha-psc)")
    parser.add_argument('-t', '--target', required=True, help="Target IP, domain, or file containing a list of targets")
    parser.add_argument('-st', '--scan-type', choices=['tcp', 'udp'], required=True, help="Scan type: TCP or UDP")
    parser.add_argument('-p', '--ports', help="Ports to scan (e.g., 80,443 or 1-1000)")
    parser.add_argument('-o', '--output', choices=['json', 'csv', 'txt'], required=True, help="Output format: json, csv, or txt")
    args = parser.parse_args()

    targets = []
    if args.target.endswith('.txt'):
        with open(args.target, 'r') as f:
            targets = [line.strip() for line in f.readlines()]
    else:
        targets = [args.target]

    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = list(map(int, args.ports.split(',')))
    else:
        ports = list(range(1, 65536))

    output_filename = f"scan_results.{args.output}"
    open(output_filename, 'w').close()  
    open("scan.log", 'w').close()  

    thread_scan(targets, ports, args.scan_type, args.output, output_filename)

    print(Fore.YELLOW + f"Scan completed. Results saved to {output_filename} and log saved to scan.log")

    
if __name__ == "__main__":
    main()