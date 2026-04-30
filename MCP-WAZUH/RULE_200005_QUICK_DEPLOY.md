# Rule 200005: Copy-Paste Deployment Guide

## 🎯 What You're Deploying

**Rule 200005** - Detect Administrator Login to Wazuh Web Server

```
Rule ID:       200005
Severity:      Level 6 (Medium - Informational)
Type:          Authentication
Description:   Detect successful administrator login to Wazuh web server
Status:        Ready to Deploy ✅
```

---

## ⚡ QUICKEST WAY: Copy & Paste to Claude

### Step 1: Copy This Exact Rule

```xml
<group name="wazuh_admin_login">
  <rule id="200005" level="6">
    <decoded_as>json</decoded_as>
    <match>successful login|admin.*login|user.*admin|administrator.*authenticated</match>
    <description>Detect successful administrator login to Wazuh web server</description>
    <group>authentication</group>
    <mitre>
      <id>T1078</id>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

### Step 2: Ask Claude

**Paste this to Claude:**
```
Use the add_wazuh_rule tool to deploy this rule with ID 200005:

<group name="wazuh_admin_login">
  <rule id="200005" level="6">
    <decoded_as>json</decoded_as>
    <match>successful login|admin.*login|user.*admin|administrator.*authenticated</match>
    <description>Detect successful administrator login to Wazuh web server</description>
    <group>authentication</group>
    <mitre>
      <id>T1078</id>
      <id>T1110</id>
    </mitre>
  </rule>
</group>

Use filename: admin_login_200005.xml
```

### Step 3: Claude Deploys It

Claude will call the `add_wazuh_rule` MCP tool and add your rule!

Expected response:
```
✓ Rule file 'admin_login_200005.xml' created successfully
✓ Rule ID 200005 is now active
```

---

## 📝 Alternative: Use the Python Script

If you want to deploy via terminal:

```bash
# Make script executable
chmod +x deploy_rule_200005.py

# Run the deployment script
python3 deploy_rule_200005.py
```

This will:
- ✅ Deploy rule 200005
- ✅ Show deployment status
- ✅ Verify the rule was added
- ✅ Provide next steps

---

## 🔍 After Deployment: Verify Rule is Active

### Method 1: Via Claude (Easiest)

Ask Claude:
```
"Show me the rules summary to verify rule 200005 was deployed"
```

### Method 2: Via Wazuh Web UI

1. Go to **Wazuh Dashboard**
2. Click **Tools** → **Ruleset**
3. Search for **"200005"**
4. You should see:
   - Rule ID: 200005
   - Description: Detect successful administrator login...
   - Level: 6

### Method 3: Via CLI (on Wazuh Manager)

```bash
# Check if rule file was created
ls -la /var/ossec/etc/rules/admin_login_200005.xml

# Search for rule in configuration
grep -n "200005" /var/ossec/etc/rules/*.xml

# Expected output:
# /var/ossec/etc/rules/admin_login_200005.xml:2:  <rule id="200005" level="6">
```

---

## 🧪 Test the Rule

### Generate a Test Alert

Create a log that matches the rule pattern:

**Option 1: Via Direct Log**
```bash
# On your monitored system
echo '{"user": "admin", "event": "successful login", "timestamp": "2024-01-16T14:30:00Z"}' | logger
```

**Option 2: Via Test Log File**
```bash
# Write to a monitored log file
echo 'User admin successful login attempt' >> /var/log/auth.log
```

**Option 3: Via Wazuh Web Form**
- Use the test/alert triggering feature in Wazuh UI

### Expected Alert

After 1-5 minutes, you should see an alert with:
```
Rule ID:    200005
Severity:   Level 6
Group:      authentication
Message:    Detect successful administrator login to Wazuh web server
```

---

## 📊 Checking for Alerts from Rule 200005

### Via Claude

```
"Show me all alerts from the last 24 hours with rule ID 200005"
```

OR

```
"Get alerts from rule 200005 to verify it's working"
```

### Via Wazuh Web UI

1. Go to **Security Events**
2. Use filter: `rule.id: 200005`
3. View all alerts triggered by this rule

### Via CLI

```bash
# Search alerts for rule 200005
grep "200005" /var/ossec/logs/alerts/alerts.json | head -20

# Or watch in real-time
tail -f /var/ossec/logs/alerts/alerts.json | grep "200005"
```

---

## 🎯 Rule Pattern Matching Explained

The rule triggers on ANY of these:

| Pattern | Matches | Examples |
|---------|---------|----------|
| `successful login` | Exact phrase | "successful login", "user successful login from IP" |
| `admin.*login` | "admin" → anything → "login" | "admin login", "admin user login" |
| `user.*admin` | "user" → anything → "admin" | "user admin", "user is admin" |
| `administrator.*authenticated` | "admin" → anything → "auth" | "administrator authenticated", "admin fully authenticated" |

**Real-world examples that WILL trigger:**
- ✅ "User admin successful login"
- ✅ "admin successful login from 192.168.1.1"
- ✅ "admin login accepted"
- ✅ "user admin authenticated"
- ✅ "administrator authenticated to Wazuh web server"
- ✅ "successful login by administrator"

---

## 📁 File Locations

After deployment, your rule files will be at:

```
Wazuh Manager Rule File:
/var/ossec/etc/rules/admin_login_200005.xml

Also referenced in:
/var/ossec/etc/rules/custom_rules.xml

Generated Rule Example File:
./example_rules/admin_login_detection_200005.xml
```

---

## ⚙️ If Rule Doesn't Work

### Problem: Rule not appearing after adding

**Solution:**
```bash
# Restart Wazuh manager
sudo systemctl restart wazuh-manager

# Check for errors
sudo tail -50 /var/ossec/logs/ossec.log | grep -i error
```

### Problem: Rule appears but no alerts

**Solutions:**
1. Check log source is being monitored
2. Verify log format has "json" decoder
3. Test with sample logs matching the pattern
4. Check agent connectivity to manager
5. Increase log level temporarily

### Problem: "Invalid XML" error

**Solution:**
- Make sure you copy the XML EXACTLY
- Check for special characters
- Validate XML structure

---

## 🔧 Customizing the Rule

### Change Severity (if needed)

High-priority logins (severity 8):
```xml
<rule id="200005" level="8">  <!-- Changed from 6 to 8 -->
  ...
</rule>
```

### Add More Specific Patterns

For Wazuh dashboard only:
```xml
<match>wazuh.*admin.*login|wazuh.*dashboard.*admin</match>
```

For specific IP ranges:
```xml
<match>admin.*login.*192\.168\.|admin.*login.*10\.0\.</match>
```

---

## 📋 Deployment Checklist

- [ ] Rule content copied exactly
- [ ] Asked Claude to deploy OR ran Python script
- [ ] Rule 200005 appears in rules list
- [ ] Wazuh manager restarted (if needed)
- [ ] Test log created
- [ ] Alert appeared for test log
- [ ] Alert has rule ID 200005
- [ ] Alert severity is level 6
- [ ] Rule appears searchable in dashboard

---

## 🚀 You're Done!

Your Wazuh system now monitors for administrator logins!

**What happens next:**
1. ✅ Any administrator login to Wazuh web server triggers an alert
2. ✅ Alerts appear in Security Events with Rule ID 200005
3. ✅ Alerts are categorized as "authentication" group
4. ✅ You can set up automated responses if needed

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| **Deploy Rule** | Ask Claude to add the rule above |
| **Check If Active** | `grep 200005 /var/ossec/etc/rules/*.xml` |
| **View Recent Alerts** | `grep 200005 /var/ossec/logs/alerts/alerts.json` |
| **Restart Manager** | `sudo systemctl restart wazuh-manager` |
| **View Rule Content** | `grep -A 10 "id=\"200005\"" /var/ossec/etc/rules/*.xml` |
| **Check for Errors** | `sudo tail -100 /var/ossec/logs/ossec.log \| grep error` |

---

**Status**: ✅ Ready to Deploy  
**Rule ID**: 200005  
**Last Updated**: 2024-01-16
