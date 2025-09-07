#!/usr/bin/env python3
import argparse, csv, json, re, glob
from pathlib import Path
from engine.schema import Event

def write_ndjson(objs, path: Path):
    with path.open("w", encoding="utf-8") as f:
        for o in objs:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")

def parse_syslog_line(line: str):
    # very lenient parse
    m = re.search(r'(\w{3}\s+\d{1,2}\s[\d:]{8})\s+(\S+)\s+(\S+)\[\d+\]:\s(.+)', line)
    if not m: 
        return None
    ts, host, proc, msg = m.groups()
    e = Event(time=ts, host=host, message=msg, sourcetype="syslog")
    # annotate auth failures
    if "Failed password" in msg and "ssh" in msg:
        e.event_type = "auth_failed"
        e.extra = {"service": "ssh", "attempts": 1}
        # crude IP extract
        ipm = re.search(r'from\s(\d+\.\d+\.\d+\.\d+)', msg)
        if ipm: e.src_ip = ipm.group(1)
    return e.__dict__

def parse_win_csv(path: Path):
    events = []
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            e = Event(time=row.get("time",""), host=row.get("host",""), user=row.get("user",""),
                      message=row.get("message",""), sourcetype="winlog")
            if row.get("event_id") == "4625":
                e.event_type = "auth_failed"
                e.extra = {"service": "windows", "attempts": 1}
            events.append(e.__dict__)
    return events

def parse_pcap_csv(path: Path):
    events = []
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            e = Event(
                time=row.get("_ws.col.Time",""),
                src_ip=row.get("ip.src",""),
                src_port=int(row.get("tcp.srcport","0") or 0),
                dst_ip=row.get("ip.dst",""),
                dst_port=int(row.get("tcp.dstport","0") or 0),
                proto=row.get("_ws.col.Protocol",""),
                sourcetype="pcap",
                event_type="conn",
                message="connection"
            )
            events.append(e.__dict__)
    return events

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", help="pcap CSV path from collector/pcap_to_csv.py")
    ap.add_argument("--syslog", nargs="*", default=[], help="syslog files (glob ok)")
    ap.add_argument("--win", nargs="*", default=[], help="Windows event CSVs")
    ap.add_argument("-o","--out", dest="out", required=True, help="Output NDJSON path")
    args = ap.parse_args()

    events = []

    if args.syslog:
        for g in args.syslog:
            for p in glob.glob(g):
                for line in Path(p).read_text().splitlines():
                    e = parse_syslog_line(line)
                    if e: events.append(e)

    if args.win:
        for g in args.win:
            for p in glob.glob(g):
                events.extend(parse_win_csv(Path(p)))

    if args.pcap:
        events.extend(parse_pcap_csv(Path(args.pcap)))

    write_ndjson(events, Path(args.out))
    print(f"Wrote {len(events)} events -> {args.out}")

if __name__ == "__main__":
    main()
