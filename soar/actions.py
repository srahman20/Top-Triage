#!/usr/bin/env python3
import os, json, requests

WEBHOOK = os.getenv('SLACK_WEBHOOK_URL','')

def slack_notify(alert: dict):
    if not WEBHOOK: 
        return
    text = f"P{alert.get('priority')} {alert.get('rule_id')} | {alert.get('src_ip')} → {alert.get('dst_ip')}:{alert.get('dst_port','')} | risk={alert.get('risk')}"
    try:
        requests.post(WEBHOOK, json={"text": text}, timeout=5)
    except Exception as e:
        pass

def suggest_block(alert: dict):
    ip = alert.get('src_ip')
    if not ip: return
    with open('outputs/block_suggestions.txt','a') as f:
        f.write(f"block drop from {ip} to any\n")

def email_notify(alert: dict):
    # Placeholder for SMTP/SendGrid integration
    pass
