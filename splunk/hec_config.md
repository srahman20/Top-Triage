# Splunk HEC Setup (local lab)
1) Settings → Data Inputs → HTTP Event Collector → New Token
2) Name: `Top-Triage HEC`, Source type: `toptriage:alerts`, Index: `toptriage` (create if needed)
3) Copy the token value and update `configs/.env.example` as `SPLUNK_HEC_TOKEN`.
4) Ensure HEC is enabled and listening on 8088 (Global Settings).

## Test with curl
```
export SPLUNK_HEC_URL=https://127.0.0.1:8088/services/collector
export SPLUNK_HEC_TOKEN=YOURTOKEN
curl -k -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" -d '{"event":{"hello":"world"},"sourcetype":"toptriage:alerts"}' $SPLUNK_HEC_URL
```
