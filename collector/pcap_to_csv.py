#!/usr/bin/env python3
import argparse, subprocess, sys, shutil, csv, os

def main():
    ap = argparse.ArgumentParser(description="Convert PCAP to CSV via tshark")
    ap.add_argument("pcap", help="path to .pcap/.pcapng")
    ap.add_argument("-o", "--output", required=True, help="output CSV path")
    args = ap.parse_args()

    if not shutil.which("tshark"):
        print("ERROR: tshark not found. Install Wireshark/tshark and retry.", file=sys.stderr)
        sys.exit(2)

    fields = [
        "-e", "_ws.col.Time",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "_ws.col.Protocol"
    ]

    cmd = ["tshark", "-r", args.pcap, "-T", "fields"] + fields + ["-E", "header=y", "-E", "separator=,"]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        sys.exit(proc.returncode)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(proc.stdout)

    print(f"Wrote CSV to {args.output}")
if __name__ == "__main__":
    main()
