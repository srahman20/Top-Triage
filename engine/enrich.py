#!/usr/bin/env python3
import argparse, csv, json
from pathlib import Path

def load_map_csv(path, key_col, val_col):
    m = {}
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            m[row[key_col]] = row[val_col]
    return m

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", required=True, help="correlated NDJSON input")
    ap.add_argument("--assets", required=True, help="assets.csv")
    ap.add_argument("--rep", required=True, help="rep_local.csv")
    ap.add_argument("-o","--out", required=True, help="enriched NDJSON output")
    args = ap.parse_args()

    assets = load_map_csv(args.assets, "host", "criticality")
    rep = load_map_csv(args.rep, "ip", "rep_score")

    out = []
    with open(args.events) as f:
        for line in f:
            if not line.strip(): continue
            a = json.loads(line)
            dst_host = a.get("dst_ip","")
            # asset enrichment by host not IP in this stub; you can map IP→host if you maintain inventory
            a["asset_criticality"] = assets.get(a.get("dst_host",""), "Medium")
            a["rep_score"] = int(rep.get(a.get("src_ip","0.0.0.0"), 50))
            out.append(a)

    with open(args.out,"w") as g:
        for a in out:
            g.write(json.dumps(a)+"\n")
    print(f"Wrote {len(out)} enriched alerts -> {args.out}")

if __name__ == "__main__":
    main()
