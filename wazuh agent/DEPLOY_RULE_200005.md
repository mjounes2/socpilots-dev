# Deploying Admin Login Detection Rule (ID: 200005)

## 📋 Rule Details

**Rule ID**: 200005  
**Rule Name**: Detect successful administrator login to Wazuh web server  
**Severity Level**: 6 (Medium)  
**Status**: Ready to Deploy

---

## ✅ Rule Content

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

---

## 🚀 Step 1: How to Add This Rule via MCP Server

### Option A: Via Claude (Easiest)
Ask Claude:
```
"Add this Wazuh rule with ID 200005 to detect administrator logins:
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
</group>"
```

Claude will automatically use the `add_wazuh_rule` tool to deploy it!

### Option B: Via Terminal/API Call
```bash
# Using the test script to add the rule
python3 test_add_rule.py
```

---

## 📍 Step 2: Where to Find Rules After Adding

After deploying the rule, check these locations:

### On Wazuh Manager (Linux)
```bash
# Custom rules location
ls -la /var/ossec/etc/rules/

# Check if rule was added
grep "200005" /var/ossec/etc/rules/*.xml

# View custom_rules.xml file
cat /var/ossec/etc/rules/custom_rules.xml
```

### Check via Wazuh Web UI
1. Go to **Wazuh Dashboard**
2. Navigate to **Tools → Ruleset**
3. Search for Rule ID **200005**
4. Verify rule details and patterns

---

## ✔️ Step 3: Verify Rule Deployment

### Check Manager Logs
```bash
tail -f /var/ossec/logs/ossec.log | grep "200005"
```

### Expected Output
```
2024-01-16 14:30:45 ossec-rulesd: INFO: Rule 200005 loaded successfully
```

### Using MCP Tools
Ask Claude:
```
"Get Wazuh rules summary to verify rule 200005 was added successfully"
```

---

## 🎯 Step 4: Test the Rule

### Generate Test Logs
Create a test log entry to trigger the rule:

```bash
# On agent or log source
echo '{"user": "admin", "event": "successful login", "timestamp": "2024-01-16T14:30:00Z"}' | logger

# Or directly in a monitored log file
echo '{"user": "administrator", "event": "authenticated to wazuh web server", "ip": "192.168.1.100"}' >> /var/log/test.log
```

### Monitor Alerts
Ask Claude:
```
"Show me alerts from the last hour with rule ID 200005"
```

Or check via Wazuh Web UI:
1. Go to **Security Events**
2. Filter by `rule.id: 200005`
3. Verify admin login alerts appear

---

## 🔍 Rule Breakdown

| Component | Value | Explanation |
|-----------|-------|-------------|
| **Rule ID** | 200005 | Unique identifier for this rule |
| **Level** | 6 | Medium severity (informational login event) |
| **Decoded As** | json | Expects JSON formatted logs |
| **Match Pattern** | `successful login\|admin.*login\|..` | Matches admin login patterns |
| **Group** | authentication | Categorized as auth event |
| **MITRE ID** | T1078, T1110 | Valid Accounts, Brute Force |

---

## 🔧 Rule Patterns Explained

The rule matches logs containing ANY of these patterns:

1. **`successful login`** - Literal string for login success
2. **`admin.*login`** - "admin" followed by anything, then "login"
3. **`user.*admin`** - "user" followed by anything, then "admin"
4. **`administrator.*authenticated`** - Admin accounts being authenticated

Example matching logs:
```
✅ "successful login by user admin"
✅ "admin login accepted"
✅ "user admin authenticated"
✅ "administrator authenticated to wazuh"
✅ "successful login from IP 192.168.1.100"
```

---

## 📊 Severity Levels Quick Reference

| Level | Category | Use Case |
|-------|----------|----------|
| **6** | Informational | ← **This Rule** (Normal admin logins) |
| 3-4 | Low | General system messages |
| 7-8 | Medium-High | Suspicious activity |
| 9-10 | High | Attack indicators |
| 11-15 | Critical | Active attacks |

---

## ⚙️ Advanced Configuration

### If You Need Higher Severity
For critical/high-priority logins, change level to 8-10:

```xml
<rule id="200005" level="8">  <!-- Changed from 6 to 8 -->
  ...
</rule>
```

### If You Need More Specific Patterns
Replace the match section with more specific patterns:

```xml
<!-- Example: Only Wazuh API admin logins -->
<match>admin.*wazuh.*successful|wazuh.*admin.*login</match>

<!-- Example: Only from specific IPs -->
<match>admin.*login.*192\.168\.1\..*</match>
```

---

## ✨ Integration with Other Tools

After deploying this rule, you can:

### Get Rule Summary
```
"Show me the rules summary to see rule 200005 statistics"
```

### Monitor Alerts
```
"Get alerts from the last 24 hours for rule 200005"
```

### Debug Issues
```
"Search manager logs for any errors related to rule 200005"
```

### Generate Reports
```
"Generate a daily security report including rule 200005 alerts"
```

---

## 🐛 Troubleshooting

### Rule Not Showing Up

**Problem**: Can't find rule 200005 after adding  
**Solutions**:
1. Restart Wazuh manager: `systemctl restart wazuh-manager`
2. Check syntax: Use the XML validation tool
3. Verify file location: Check `/var/ossec/etc/rules/custom_rules.xml`

### Rule Not Triggering Alerts

**Problem**: Rule added but no alerts generated  
**Solutions**:
1. Check log source is being monitored
2. Verify log format matches JSON decoder
3. Test pattern manually with sample logs
4. Increase log detail level temporarily
5. Check manager logs for decoder errors

### "Invalid XML" Error

**Problem**: Error when adding the rule  
**Solutions**:
1. Copy the rule XML exactly as shown above
2. No extra spaces or special characters
3. Validate XML before adding

---

## 📁 Files Provided

**Ready-to-Deploy Rule File:**
```
example_rules/admin_login_detection_200005.xml
```

Copy this file to your Wazuh manager:
```bash
scp example_rules/admin_login_detection_200005.xml \
    root@wazuh-manager:/var/ossec/etc/rules/
```

---

## ✅ Deployment Checklist

- [ ] Rule content reviewed and verified
- [ ] Rule ID 200005 confirmed
- [ ] Rule added via MCP server or API
- [ ] Wazuh manager restarted (if needed)
- [ ] Rule appears in rules summary
- [ ] Rule ID 200005 is searchable
- [ ] Test logs created
- [ ] Alerts generated for test logs
- [ ] Alert severity is level 6
- [ ] Rule appears in security events

---

## 🎓 Next Steps

1. **Deploy Now**: Ask Claude to add the rule
2. **Verify**: Check rule summary to confirm
3. **Test**: Generate test logs to trigger the rule
4. **Monitor**: Watch for real admin login alerts
5. **Adjust**: Modify patterns or severity as needed

---

## 📞 Quick Command Reference

```bash
# Add rule to custom_rules.xml
cat example_rules/admin_login_detection_200005.xml >> \
    /var/ossec/etc/rules/custom_rules.xml

# Verify rule was added
grep -A 10 "id=\"200005\"" /var/ossec/etc/rules/custom_rules.xml

# Check for rule parsing errors
tail -50 /var/ossec/logs/ossec.log | grep -i "rule\|error"

# Restart Wazuh to load new rules
systemctl restart wazuh-manager

# Search for alerts from this rule
tail -f /var/ossec/logs/alerts/alerts.json | grep "200005"
```

---

**Rule Status**: ✅ Ready to Deploy  
**Rule ID**: 200005  
**Last Updated**: 2024-01-16
