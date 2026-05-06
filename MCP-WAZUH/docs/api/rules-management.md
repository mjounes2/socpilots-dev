# Add Wazuh Rules Feature

## Overview

The Wazuh MCP Server now supports adding custom detection rules through the `add_wazuh_rule` tool. This allows you to dynamically create and deploy new Wazuh detection rules in XML format without manually editing configuration files.

## Features

✅ **Add Custom Rules** - Create new detection rules in XML format  
✅ **XML Validation** - Validates rule XML structure before adding  
✅ **File Management** - Automatically manages rule file names  
✅ **Cache Invalidation** - Updates rule cache after adding new rules  
✅ **Error Handling** - Comprehensive error messages for troubleshooting  
✅ **Security** - Validates input size and prevents path traversal  

## Tool: `add_wazuh_rule`

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `rule_content` | string | Yes | - | XML content of the rule(s) to add. Must be valid XML format with `<rule>` elements. |
| `rule_filename` | string | No | `custom_rules.xml` | Name of the rule file to create (e.g., `my_rules.xml`). The `.xml` extension is added automatically if omitted. |
| `overwrite` | boolean | No | `false` | When `true`, overwrites an existing rule file with the same name. |

> Implementation note: The tool uploads rule files to Wazuh using `PUT /rules/files/{file_name}` with `Content-Type: application/octet-stream`. This matches Wazuh manager requirements for rule file uploads and avoids unsupported media-type failures.

### Rule Risk Level

- **Risk**: MEDIUM
- **Reversible**: Yes (rules can be removed/modified)
- **Requires**: Write permission to Wazuh rules directory

## XML Rule Format

Wazuh rules follow a specific XML structure. Here's the format of a valid rule:

```xml
<group name="group_name">
  <rule id="rule_id" level="severity_level">
    <decoded_as>decoder_name</decoded_as>
    <match>pattern_to_match</match>
    <description>Human-readable rule description</description>
    <group>category</group>
    <mitre>
      <id>MITRE_TECHNIQUE_ID</id>
      ...
    </mitre>
  </rule>
</group>
```

### Rule Elements

- **rule** (required)
  - `id` (required): Unique numeric rule ID (typically 100000+)
  - `level` (required): Severity level 0-15 (higher = more severe)
  
- **decoded_as**: Log decoder to apply
- **match**: Pattern to match in log (regex supported)
- **description**: Human-readable description of what the rule detects
- **group**: Rule category/group
- **mitre**: MITRE ATT&CK framework mapping
  - **id**: MITRE technique IDs (e.g., T1078, T1110)

## Usage Examples

### Example 1: Administrator Login Detection

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

**Using in Claude:**
```
Add this Wazuh rule to detect administrator logins:
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

### Example 2: Suspicious Process Detection

```xml
<group name="malware_detection,">
  <rule id="200002" level="10">
    <decoded_as>json</decoded_as>
    <match>cmd.exe|powershell.exe</match>
    <description>Detect execution of command shell or PowerShell from unusual location</description>
    <group>process_execution</group>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>
</group>
```

### Example 3: Multiple Rules in One File

```xml
<group name="custom_rules,">
  <rule id="200010" level="3">
    <decoded_as>json</decoded_as>
    <match>user logged in</match>
    <description>User authentication event</description>
    <group>authentication</group>
  </rule>
  
  <rule id="200011" level="8">
    <decoded_as>json</decoded_as>
    <match>failed.*attempts</match>
    <description>Multiple failed authentication attempts</description>
    <group>authentication</group>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

## API Response

### Success Response

```json
{
  "data": {
    "status": "success",
    "message": "Rule file 'admin_login_detection.xml' created successfully",
    "file_name": "admin_login_detection.xml",
    "affected_items": [...]
  }
}
```

### Error Responses

**Invalid XML:**
```
Error: Invalid XML format: no element found: line 1, column 0
```

**Unsupported Media Type:**
```
Error: Invalid Content-Type (application/xml), expected ['application/octet-stream']
```

This tool automatically uses `Content-Type: application/octet-stream` for Wazuh rule file uploads.

**Missing Required Parameter:**
```
Error: Invalid parameter 'rule_content': is required and cannot be empty
```

**Rule Content Too Large:**
```
Error: Invalid parameter 'rule_content': exceeds maximum size of 1MB
```

## Validation Rules

1. **XML Format**: Must be valid, well-formed XML
2. **Rule ID**: Should be unique (typically > 100000)
3. **Rule Level**: Must be 0-15
4. **File Size**: Maximum 1MB for rule content
5. **Filename**: Automatically sanitized to prevent path traversal

## Best Practices

### Rule ID Selection

- **0-4999**: Wazuh built-in rules (reserved)
- **5000-99999**: Standard distribution rules
- **100000+**: **Custom rules** (your organization's rules)

### Rule Severity Levels

| Level | Severity | Use Case |
|-------|----------|----------|
| 0-2 | Ignore | Not interesting events |
| 3-4 | Low | System messages |
| 5-6 | Informational | User authentication |
| 7-8 | Medium | Potential suspicious |
| 9-10 | High | Suspicious activity |
| 11-13 | Severe | Attack attempt |
| 14-15 | Critical | High impact attacks |

### Rule Naming Conventions

```xml
<!-- Good: Clear, descriptive names -->
<rule id="200001" level="5">
  <description>Detect failed SSH login from suspicious IP</description>
</rule>

<!-- Avoid: Vague or generic -->
<rule id="200001" level="5">
  <description>Login rule</description>
</rule>
```

### MITRE ATT&CK Mapping

Map your rules to MITRE ATT&CK framework techniques:

```xml
<mitre>
  <id>T1078</id>  <!-- Valid Accounts -->
  <id>T1110</id>  <!-- Brute Force -->
</mitre>
```

## Troubleshooting

### "Invalid XML format" Error

**Cause**: Rule XML is malformed  
**Solution**: 
- Verify all tags are properly closed
- Check for special characters that need escaping
- Validate XML using an XML validator tool

### "Rule file creation failed" Error

**Cause**: Wazuh API returned an error  
**Solution**:
- Check Wazuh is running and accessible
- Verify authentication credentials
- Ensure rule ID doesn't conflict with existing rules
- Check Wazuh rules directory permissions

### Rule Not Appearing in Alerts

**Cause**: Rule not activated or matching conditions not met  
**Solution**:
- Verify rule XML is valid (no parse errors)
- Check log source is being monitored
- Ensure log format matches `decoded_as` decoder
- Test `<match>` pattern against sample logs
- Check Wazuh manager logs for rule loading errors

## Advanced Usage

### Testing Rules Before Adding

```
Ask Claude: "Validate this XML rule format for errors"
[paste your rule XML]
```

### Multiple Rules at Once

You can add multiple rules in a single file:

```
Add these detection rules to Wazuh:
<group name="security_team,">
  <rule id="200020" level="5">
    <description>Rule 1</description>
  </rule>
  <rule id="200021" level="5">
    <description>Rule 2</description>
  </rule>
</group>
```

## Integration with Other Tools

The `add_wazuh_rule` tool works seamlessly with:

- **get_wazuh_rules_summary** - View rule statistics after adding
- **get_wazuh_alerts** - See alerts from your new rules
- **search_wazuh_manager_logs** - Debug rule parsing issues
- **run_compliance_check** - Verify rules align with compliance frameworks

## See Also

- [Wazuh Official Rules Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Wazuh Decoders Reference](https://documentation.wazuh.com/current/user-manual/ruleset/decoders.html)
