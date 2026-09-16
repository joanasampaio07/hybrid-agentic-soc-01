# 🛡️ Wazuh SIEM Integration & Native OpenSearch Plugin

This directory contains the Wazuh configuration files, custom high-risk rules, integration scripts, and the custom OpenSearch Dashboards plugin.

## 📁 Files & Directories
- **`custom-n8n`**: Webhook integration script placed in `/var/ossec/integrations/custom-n8n` to forward alerts to n8n or the FastAPI platform.
- **`local_rules.xml`**: High-risk correlation rules (Brute Force Level 12, Sudo/User creation Level 13).
- **`wazuhAiSoc-plugin/`**: Custom OpenSearch Dashboards plugin adding a dedicated AI SOC tab to the Wazuh interface.

## 🛠️ Wazuh Setup Instructions

### 1. Configure the Integration Script
On the Wazuh Manager:
```bash
sudo cp custom-n8n /var/ossec/integrations/custom-n8n
sudo chmod +x /var/ossec/integrations/custom-n8n
sudo chown root:wazuh /var/ossec/integrations/custom-n8n
```

Add to `/var/ossec/etc/ossec.conf`:
```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>http://<BACKEND_OR_N8N_IP>:8000/api/alerts</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

### 2. Add Custom Detection Rules
Copy `local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` and restart Wazuh Manager:
```bash
sudo systemctl restart wazuh-manager
```

### 3. Install the `wazuhAiSoc` Plugin
Copy `wazuhAiSoc-plugin` to `/usr/share/wazuh-dashboard/plugins/` and restart the dashboard:
```bash
sudo systemctl restart wazuh-dashboard
```
