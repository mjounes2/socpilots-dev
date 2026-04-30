# Quick Reference: Add Wazuh Rules

## Quick Start

### Your Example Rule (Can Now Be Added!)

```xml
<group name="wazuh,">
  <rule id="200001" level="5">
    <decoded_as>json</decoded_as>
    <match>successful login</match>
    <description>Detect successful administrator login to Wazuh web server</description>
    <group>authentication</group>
    <mitre>
      <id>T1078</id>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

### How to Add It

**Using Claude:**
> "Please add this Wazuh rule: [paste your XML above]"

**Response will be:**
```json
{
  "status": "success",
  "message": "Rule file 'custom_rules.xml' created successfully",
  "file_name": "custom_rules.xml"
}
```

---

## Basic Rule Template

```xml
<group name="my_rules">
  <rule id="100001" level="5">
    <decoded_as>json</decoded_as>              <!-- Log decoder -->
    <match>pattern_here</match>                <!-- What to match -->
    <description>Rule description</description> <!-- Human readable -->
    <group>category</group>                    <!-- Rule category -->
  </rule>
</group>
```

---

## Severity Levels Quick Guide

| Level | Type | Example |
|-------|------|---------|
| 0-2 | Ignore | System noise |
| 3-4 | Low | General info |
| 5-6 | Medium | User actions |
| 7-8 | High | Suspicious |
| 9-10 | Severe | Attack likely |
| 11-13 | Critical | Active attack |
| 14-15 | Emergency | Critical breach |

---

## Common Patterns

### Authentication Event
```xml
<rule id="100010" level="5">
  <decoded_as>json</decoded_as>
  <match>user logged in|login successful</match>
  <description>User authentication event</description>
  <group>authentication</group>
</rule>
```

### Failed Login (High Alert)
```xml
<rule id="100011" level="10">
  <decoded_as>json</decoded_as>
  <match>failed.*login|authentication.*failed</match>
  <description>Multiple failed authentication attempts</description>
  <group>authentication</group>
  <mitre><id>T1110</id></mitre>
</rule>
```

### Process Execution
```xml
<rule id="100012" level="8">
  <decoded_as>json</decoded_as>
  <match>cmd.exe|powershell.exe</match>
  <description>Suspicious shell execution detected</description>
  <group>process_execution</group>
  <mitre><id>T1059</id></mitre>
</rule>
```

### File Access
```xml
<rule id="100013" level="6">
  <decoded_as>json</decoded_as>
  <match>/etc/passwd|/etc/shadow</match>
  <description>Sensitive file access detected</description>
  <group>file_access</group>
</rule>
```

---

## Tool Parameters

### Required
- **rule_content** (string) - Your XML rule content

### Optional
- **rule_filename** (string) - File name for rule (default: `custom_rules.xml`)

### Limits
- Maximum rule content size: **1 MB**
- Rule ID: Use **100000+** for custom rules
- Severity: **0-15**

---

## Testing Your Rules

1. **Before Adding**: Validate XML format
   ```
   "Is this XML valid? [paste rule]"
   ```

2. **After Adding**: Check if rule is active
   ```
   "Get rule summary to verify new rule was added"
   ```

3. **See Alerts**: View alerts triggered by your rule
   ```
   "Show me alerts from rule 200001"
   ```

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| "Invalid XML format" | Check all tags closed, special chars escaped |
| "rule_content is required" | Provide the rule XML content |
| "exceeds maximum size" | Split into multiple rule files |
| Rule not firing | Verify decoder matches log source |
| Wrong severity | Adjust level (0-15) based on threat |

---

## MITRE ATT&CK Mapping Examples

Add these to your rules:

```xml
<mitre>
  <id>T1078</id>   <!-- Valid Accounts -->
  <id>T1110</id>   <!-- Brute Force -->
  <id>T1059</id>   <!-- Command and Scripting Interpreter -->
  <id>T1547</id>   <!-- Boot or Logon Autostart Execution -->
</mitre>
```

---

## Naming Convention for Rule IDs

- **0-4999**: Wazuh built-in (reserved)
- **5000-99999**: Distribution rules
- **100000-199999**: Your first set of rules ✅
- **200000+**: Additional custom rules ✅

---

## Integration with Other Tools

After adding a rule:

1. **View Rule Summary**
   ```
   "Show me the rules summary"
   ```

2. **Check for Alerts**
   ```
   "Get alerts from the last hour"
   ```

3. **Monitor Manager Logs**
   ```
   "Search manager logs for rule parsing errors"
   ```

---

## Advanced: Multiple Rules in One File

```xml
<group name="custom_rules">
  <rule id="100020" level="3">
    <description>Rule 1</description>
  </rule>
  
  <rule id="100021" level="8">
    <description>Rule 2</description>
  </rule>
  
  <rule id="100022" level="5">
    <description>Rule 3</description>
  </rule>
</group>
```

All rules will be added in the same operation.

---

## File References

- 📖 **Full Documentation**: [docs/api/rules-management.md](../docs/api/rules-management.md)
- 🧪 **Test Script**: [test_add_rule.py](./test_add_rule.py)
- 📋 **Implementation Details**: [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md)

---

## Status

✅ **Feature Complete & Production Ready**

- XML validation working
- MCP tool integrated
- Documentation complete
- Test script included
- No syntax errors
- Your example rule can be added!
