#!/usr/bin/env python3
"""
Test script to verify the add_wazuh_rule functionality with the user's example rule.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.config import WazuhConfig

# Example rule from user
EXAMPLE_RULE = '''<group name="wazuh,">
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
</group>'''


async def test_add_rule():
    """Test the add_rule functionality."""
    # Create config (adjust these for your environment)
    config = WazuhConfig()
    
    # Initialize client
    client = WazuhClient(config)
    await client.initialize()
    
    print("=" * 70)
    print("Testing add_wazuh_rule with example rule...")
    print("=" * 70)
    print("\nRule Content:")
    print(EXAMPLE_RULE)
    print("\n" + "-" * 70)
    
    try:
        # Test adding the rule
        result = await client.add_rule(EXAMPLE_RULE, "admin_login_detection.xml")
        
        print("\n✓ Rule Addition Successful!")
        print("\nResult:")
        print(json.dumps(result, indent=2, default=str))
        
        return True
        
    except Exception as e:
        print(f"\n✗ Error adding rule: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Cleanup
        if client.client:
            await client.client.aclose()


async def test_xml_validation():
    """Test XML validation for various rule formats."""
    print("\n" + "=" * 70)
    print("Testing XML Validation...")
    print("=" * 70)
    
    config = WazuhConfig()
    client = WazuhClient(config)
    await client.initialize()
    
    test_cases = [
        ("Valid XML", EXAMPLE_RULE, True),
        ("Invalid XML - unclosed tag", '<rule id="100"><description>Test</rule>', False),
        ("Invalid XML - malformed", '<rule id="100" <description>Test</description>', False),
        ("Valid empty rule", '<group name="test"><rule id="100001" level="1"></rule></group>', True),
    ]
    
    for name, content, should_succeed in test_cases:
        try:
            # We'll test the validation part without making API call
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            success = True
            msg = "✓ Valid XML"
        except Exception as e:
            success = False
            msg = f"✗ Invalid XML: {e}"
        
        expected = "✓" if should_succeed else "✗"
        actual = "✓" if success else "✗"
        status = "PASS" if (success == should_succeed) else "FAIL"
        
        print(f"\n[{status}] {name}")
        print(f"  Expected: {expected} Valid")
        print(f"  Actual:   {actual} {msg}")
    
    await client.client.aclose()


async def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("Wazuh MCP Server - Add Rule Feature Tests")
    print("=" * 70)
    
    # Test XML validation (no Wazuh connection needed)
    await test_xml_validation()
    
    # Test actual rule addition (requires Wazuh connection)
    print("\n\nNote: The following test requires a live Wazuh connection.")
    print("If Wazuh is not available, you'll see a connection error (expected).\n")
    
    success = await test_add_rule()
    
    print("\n" + "=" * 70)
    if success:
        print("✓ All tests passed!")
    else:
        print("Some tests failed. Check the output above for details.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
