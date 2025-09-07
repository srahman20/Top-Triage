import json, tempfile, os
from engine import correlate as C

def test_bruteforce_threshold(tmp_path):
    events_path = tmp_path/"events.jsonl"
    with open(events_path,"w") as f:
        f.write('{"event_type":"auth_failed","extra":{"service":"ssh","attempts":6},"src_ip":"1.2.3.4","dst_ip":"10.0.0.5"}\n')
    rules = {"rules":[{"id":"brute_force_ssh","count":{"threshold":5}}]}
    # monkey-patch loader
    evs = list(C.load_events(events_path))
    alerts = list(C.brute_force_ssh(evs, threshold=5))
    assert any(a["rule_id"]=="brute_force_ssh" for a in alerts)
