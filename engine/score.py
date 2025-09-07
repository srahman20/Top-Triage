#!/usr/bin/env python3
import argparse, json, math, csv

def base_score(sev):
    return {"low":10, "medium":25, "high":50}.get(sev, 10)

def priority(risk):
    if risk >= 80: return "P1"
    if risk >= 60: return "P2"
    if risk >= 40: return "P3"
    return "P4"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True, help="enriched NDJSON input")
    ap.add_argument("-o","--out", required=True, help="scored NDJSON output")
    ap.add_argument("--csv", required=True, help="CSV output for Splunk file ingest")
    args = ap.parse_args()

    out = []
    with open(args.events) as f:
        for line in f:
            if not line.strip(): continue
            a = json.loads(line)
            attempts = int(a.get("extra",{}).get("attempts", 0))
            distinct_ports = int(a.get("extra",{}).get("distinct_ports", 0))
            rep = int(a.get("rep_score", 50))
            crit = {"Low":0, "Medium":5, "High":15, "Crown":30}.get(a.get("asset_criticality","Medium"), 5)

            risk = base_score(a.get("severity","low")) \
                 + (math.log10(attempts+1) * 10 if attempts else 0) \
                 + (math.log10(distinct_ports+1) * 10 if distinct_ports else 0) \
                 + (rep/5.0) \
                 + crit

            a["risk"] = round(risk, 2)
            a["priority"] = priority(risk)
            out.append(a)

    with open(args.out,"w") as g:
        for a in out:
            g.write(json.dumps(a)+"\n")

    # CSV for Splunk
    fields = ["_time","priority","risk","rule_id","src_ip","dst_ip","dst_port","user","message"]
    with open(args.csv, "w", newline="") as g:
        w = csv.DictWriter(g, fieldnames=fields)
        w.writeheader()
        for a in out:
            w.writerow({
                "_time": a.get("time",""),
                "priority": a.get("priority",""),
                "risk": a.get("risk",""),
                "rule_id": a.get("rule_id",""),
                "src_ip": a.get("src_ip",""),
                "dst_ip": a.get("dst_ip",""),
                "dst_port": a.get("dst_port",""),
                "user": a.get("user",""),
                "message": a.get("message","")
            })

    print(f"Wrote {len(out)} scored alerts -> {args.out} and CSV -> {args.csv}")

if __name__ == "__main__":
    main()
