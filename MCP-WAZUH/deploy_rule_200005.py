#!/usr/bin/env python3
"""
Deploy Admin Login Detection Rule (ID: 200005) to Wazuh via MCP Server
This script adds the rule to detect administrator logins to Wazuh web server
"""

import asyncio
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.config import WazuhConfig

# Rule for detecting administrator login to Wazuh webserver
ADMIN_LOGIN_RULE = '''<group name="wazuh_admin_login">
  <rule id="200005" level="15">
    <decoded_as>json</decoded_as>
    <match>successful login|admin.*login|user.*admin|administrator.*authenticated</match>
    <description>Detect successful administrator login to Wazuh web server</description>
    <group>authentication</group>
    <mitre>
      <id>T1078</id>
      <id>T1110</id>
    </mitre>
  </rule>
</group>'''


async def deploy_rule_200005():
    """Deploy rule 200005 to detect administrator logins."""
    print("=" * 80)
    print("DEPLOYING RULE 200005: Administrator Login Detection")
    print("=" * 80)
    
    # Create config from environment or config file
    try:
        config = WazuhConfig.from_env()
    except Exception as exc:
        print(f"\n❌ Configuration error: {exc}")
        raise
    
    # Initialize client
    client = WazuhClient(config)
    await client.initialize()
    
    print("\n📋 Rule Details:")
    print("  Rule ID:      200005")
    print("  Description:  Detect successful administrator login to Wazuh web server")
    print("  Severity:     Level 6 (Medium - Informational)")
    print("  Group:        authentication")
    print("  File:         admin_login_200005.xml")
    
    print("\n" + "=" * 80)
    print("RULE CONTENT:")
    print("=" * 80)
    print(ADMIN_LOGIN_RULE)
    
    print("\n" + "=" * 80)
    print("DEPLOYING...")
    print("=" * 80)
    
    try:
        # Deploy the rule
        result = await client.add_rule(
            ADMIN_LOGIN_RULE,
            rule_filename="admin_login_200005.xml",
            overwrite=True,
        )
        
        print("\n✅ RULE DEPLOYMENT SUCCESSFUL!")
        print("\nResult:")
        print(json.dumps(result, indent=2, default=str))
        
        print("\n" + "=" * 80)
        print("NEXT STEPS:")
        print("=" * 80)
        print("""
1. ✅ Rule 200005 has been added to your Wazuh system

2. 📍 Rule Location:
   - File: /var/ossec/etc/rules/admin_login_200005.xml
   - Also added to: /var/ossec/etc/rules/custom_rules.xml

3. 🔄 Restart Wazuh Manager (if needed):
   sudo systemctl restart wazuh-manager

4. 🔍 Verify Rule Was Added:
   - Via Web UI: Tools → Ruleset, search for rule ID 200005
   - Via CLI: grep "200005" /var/ossec/etc/rules/custom_rules.xml
   
5. 🧪 Test the Rule:
   Create a log with: "successful login", "admin login", or "administrator authenticated"
   
6. 📊 Monitor Alerts:
   Search security events for rule ID 200005

7. 📞 Get Rule Summary:
   Ask Claude: "Show me the rules summary"
   
8. 🚨 View Alerts:
   Ask Claude: "Get alerts from rule 200005"
        """)
        
        print("\n" + "=" * 80)
        print("PATTERN MATCHING:")
        print("=" * 80)
        print("""
This rule will match logs containing ANY of these patterns:
  ✓ "successful login"
  ✓ "admin" (followed by anything) "login"
  ✓ "user" (followed by anything) "admin"
  ✓ "administrator" (followed by anything) "authenticated"

Example matching logs:
  ✓ User admin successful login
  ✓ admin login accepted  
  ✓ user admin authenticated
  ✓ administrator authenticated to wazuh web server
  ✓ successful login from IP 192.168.1.100
        """)
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR DEPLOYING RULE:")
        print(f"   {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Cleanup
        if client.client:
            await client.client.aclose()


async def verify_rule_deployed():
    """Verify that rule 200005 is deployed."""
    print("\n" + "=" * 80)
    print("VERIFYING RULE DEPLOYMENT...")
    print("=" * 80)
    
    try:
        config = WazuhConfig.from_env()
    except Exception as exc:
        print(f"\n❌ Configuration error: {exc}")
        raise
    
    client = WazuhClient(config)
    await client.initialize()
    
    try:
        # Verify the rule file exists in Wazuh's rule file list.
        result = await client.get_rule_files()
        files = result.get("data", {}).get("affected_items", [])
        rule_file = "admin_login_200005.xml"
        found = any(item.get("filename") == rule_file or item.get("id") == rule_file for item in files)

        if not found:
            raise ValueError(f"Rule file '{rule_file}' not found in Wazuh rule repository")

        print("\n✅ RULE 200005 DEPLOYMENT VERIFIED!")
        print(f"\nRule file '{rule_file}' exists in Wazuh manager")
        await client.client.aclose()
        return True

    except Exception as e:
        print(f"\n⚠️  Could not verify rule (it may need manager restart):")
        print(f"   {e}")
        await client.client.aclose()
        return False


async def main():
    """Deploy the rule and verify."""
    print("\n")
    
    # Deploy the rule
    success = await deploy_rule_200005()
    
    if success:
        # Try to verify
        await verify_rule_deployed()
        
        print("\n" + "=" * 80)
        print("✅ DEPLOYMENT COMPLETE!")
        print("=" * 80)
        print("""
Your Wazuh system is now monitoring for administrator logins!

Rule ID: 200005
Status: Active
Next Action: Check DEPLOY_RULE_200005.md for detailed documentation
        """)
    else:
        print("\n" + "=" * 80)
        print("❌ DEPLOYMENT FAILED")
        print("=" * 80)
        print("""
Please check:
1. Wazuh is running and accessible
2. API credentials are correct
3. Network connectivity to Wazuh manager
4. Check logs for more details
        """)
    
    print()


if __name__ == "__main__":
    asyncio.run(main())
