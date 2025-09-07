#!/usr/bin/env python3
import argparse, json, yaml
from collections import defaultdict, Counter
from pathlib import Path

def load_events(path: Path):
    with path.open() as f:
        for line in f:
            if line.strip():
                yield json.loads(line)

def brute_force_ssh(events, threshold, window=None):
    # naive: aggregate over entire input; lab-friendly
    counts = defaultdict(int)
    for e in events:
        if e.get("event_type")=="auth_failed" and e.get("extra",{}).get("service")=="ssh":
            key = (e.get("src_ip"), e.get("dst_ip"))
            counts[key] += int(e.get("extra",{}).get("attempts",1))
    for (src,dst), c in counts.items():
        if c >= threshold:
            yield {
                "rule_id":"brute_force_ssh", "src_ip":src,"dst_ip":dst,
                "message": f"SSH brute force suspected: {c} failures",
                "severity":"high", "mitre":"T1110", "extra":{"attempts":c}
            }

def port_scan_tcp(events, threshold, window=None):
    ports_by_srcdst = defaultdict(set)
    for e in events:
        if e.get("proto")=="TCP" and e.get("event_type")=="conn":
            key = (e.get("src_ip"), e.get("dst_ip"))
            dport = e.get("dst_port",0)
            if dport: ports_by_srcdst[key].add(dport)
    for (src,dst), s in ports_by_srcdst.items():
        if len(s) >= threshold:
            yield {
                "rule_id":"port_scan_tcp","src_ip":src,"dst_ip":dst,
                "message": f"Port scan suspected: {len(s)} distinct dst ports",
                "severity":"medium","mitre":"T1046","extra":{"distinct_ports":len(s)}
            }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True, help="rules.yaml path")
    ap.add_argument("--allow", default=None, help="allowlists.yaml path")
    ap.add_argument("--events", required=True, help="normalized NDJSON input")
    ap.add_argument("-o","--out", required=True, help="correlated NDJSON output")
    args = ap.parse_args()

    rules = yaml.safe_load(Path(args.rules).read_text())
    allow = {"ips":[], "users":[], "hosts":[]}
    if args.allow and Path(args.allow).exists():
        allow = yaml.safe_load(Path(args.allow).read_text())

    events = list(load_events(Path(args.events)))

    alerts = []
    # apply built-in handlers based on rules
    for rule in rules.get("rules", []):
        rid = rule.get("id")
        if rid == "brute_force_ssh":
            alerts.extend(brute_force_ssh(events, rule.get("count",{}).get("threshold",5)))
        elif rid == "port_scan_tcp":
            alerts.extend(port_scan_tcp(events, rule.get("distinct_count",{}).get("threshold",15)))

    # allowlist suppression
    def allowed(a):
        return (a.get("src_ip") in allow.get("ips",[])) or (a.get("dst_ip") in allow.get("ips",[]))

    alerts = [a for a in alerts if not allowed(a)]

    with open(args.out, "w") as f:
        for a in alerts:
            f.write(json.dumps(a)+"\n")

    print(f"Wrote {len(alerts)} alerts -> {args.out}")

if __name__ == "__main__":
    main()
