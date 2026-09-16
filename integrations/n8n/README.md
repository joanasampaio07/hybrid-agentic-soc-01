# ⚡ n8n Automation & Rule Engine Integration

This directory contains the complete n8n workflow pipeline for the Hybrid Agentic SOC.

## 📁 Files
- **`wazuh_ai_soc_workflow.json`**: The complete exportable n8n workflow definition.

## 🚀 How to Import into n8n
1. Open your self-hosted n8n instance (e.g. `http://localhost:5678` or EC2 IP).
2. Click on **Workflows** ➔ **Add Workflow** ➔ **Import from File**.
3. Select `wazuh_ai_soc_workflow.json`.
4. Configure credentials for:
   - **VirusTotal API Key** (Header Auth `x-apikey`)
   - **AbuseIPDB API Key** (Header Auth `Key`)
   - **Google Sheets OAuth** (for audit trail logging)
   - **Gmail OAuth** (for medium risk alerts)
   - **Ollama Endpoint** (`http://<OLLAMA_IP>:11434/api/generate`)
5. Activate the workflow!
