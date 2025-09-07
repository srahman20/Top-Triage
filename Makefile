hec-send:
	@echo "Sending alerts to HEC";
	@jq -c '. | {event: ., sourcetype: "toptriage:alerts"}' outputs/out_alerts.jsonl \
	 | while read line; do \
	   curl -s -k -H "Authorization: Splunk $$SPLUNK_HEC_TOKEN" \
	       -H 'Content-Type: application/json' \
	       -d "$$line" $$SPLUNK_HEC_URL; \
	 done; echo
