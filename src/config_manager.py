"""
Configuration management for SSL Certificate Manager.
Handles loading, saving, and initial setup of configurations.
"""

import json
import sys
from pathlib import Path
from datetime import datetime


class ConfigManager:
    """Handles configuration management and initial setup."""
    
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.global_config = None
        self.service_config = None
        
    def load_global_config(self):
        """Loads the global configuration from the JSON file."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                self.global_config = config
                return config
        except FileNotFoundError:
            config = self.setup_initial_config()
            self.global_config = config
            return config
        except json.JSONDecodeError:
            print(f"❌ Error reading configuration file {self.config_file}!")
            sys.exit(1)

    def load_service_config(self, service_path):
        """Loads the service-specific configuration."""
        config_path = service_path / "config.json"
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def save_service_config(self, service_path, config):
        """Saves the service-specific configuration."""
        # Create service directory if it doesn't exist
        service_path.mkdir(parents=True, exist_ok=True)
        
        config_path = service_path / "config.json"
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"❌ Error saving service configuration: {e}")
            return False

    def get_user_input(self, prompt, default=None, required=True):
        """Helper function for user inputs."""
        while True:
            if default:
                user_input = input(f"{prompt} [{default}]: ").strip()
                if not user_input:
                    return default
            else:
                user_input = input(f"{prompt}: ").strip()
            
            if user_input or not required:
                return user_input
            
            print("❌ Input is required!")

    def setup_initial_config(self):
        """Sets up the initial configuration through interactive wizard."""
        print("🆕 Welcome to SSL Certificate Manager!")
        print("=" * 50)
        print("📝 No configuration found. Let's set up your SSL environment!")
        print("\n⚠️  SECURITY NOTICE:")
        print("🏠 This tool is for HOME USE ONLY - not for production!")
        print("🔒 Keep this directory secure - it will contain sensitive crypto keys!")
        print("💡 Use strong passwords and consider encrypted storage.\n")
        
        # Try to load example config as template
        example_config = None
        example_file = Path("config.json.example")
        if example_file.exists():
            try:
                with open(example_file, 'r', encoding='utf-8') as f:
                    example_config = json.load(f)
                print("✅ Found config.json.example - using as template")
            except json.JSONDecodeError:
                print("⚠️  config.json.example is invalid - proceeding without template")
        else:
            print("💡 No config.json.example found - starting from scratch")
        
        print("\n🔧 Let's configure your Certificate Authority:")
        print("─" * 50)
        
        # Get user's name/organization
        user_name = self.get_user_input("👤 What would you like to call yourself or your organization?", 
                                       example_config and example_config.get("ca", {}).get("organization"))
        
        # Suggest CA names based on user input
        ca_suggestions = [
            f"{user_name} Root CA",
            f"{user_name} Certificate Authority", 
            f"{user_name} Private CA",
            f"{user_name} Internal CA"
        ]
        
        print(f"\n💡 Great! Here are some suggestions for your CA name:")
        for i, suggestion in enumerate(ca_suggestions, 1):
            print(f"   {i}. {suggestion}")
        print("   5. Enter custom name")
        
        while True:
            choice = input(f"\n🏛️  Choose CA name (1-5): ").strip()
            if choice in ['1', '2', '3', '4']:
                ca_name = ca_suggestions[int(choice) - 1]
                break
            elif choice == '5':
                ca_name = self.get_user_input("🏛️  Enter your CA name", f"{user_name} Root CA")
                break
            else:
                print("❌ Please choose 1-5!")
        
        print(f"\n✅ CA Name: {ca_name}")
        
        # Get location information
        print(f"\n📍 Now let's set your location:")
        
        default_ca = example_config.get("ca", {}) if example_config else {}
        
        country = self.get_user_input("🌍 Country (2 letters, e.g., US, DE, GB)", 
                                     default_ca.get("country", "US"))
        state = self.get_user_input("🏞️  State/Province (e.g., California, Bavaria, Ontario)", 
                                   default_ca.get("state", "California"))
        city = self.get_user_input("🏙️  City (e.g., San Francisco, Munich, Toronto)", 
                                  default_ca.get("city", "San Francisco"))
        
        # Get contact information
        print(f"\n📧 Contact Information:")
        
        # Suggest email based on user name
        suggested_emails = [
            f"admin@{user_name.lower().replace(' ', '-')}.local",
            f"ca@{user_name.lower().replace(' ', '-')}.local", 
            f"ssl@{user_name.lower().replace(' ', '-')}.local"
        ]
        
        default_email = default_ca.get("email", suggested_emails[0])
        email = self.get_user_input(f"📧 Email address", default_email)
        
        # Get organizational details
        print(f"\n🏢 Organizational Details:")
        
        org_unit_suggestions = [
            "IT Department",
            "Infrastructure Team", 
            "Security Team",
            "DevOps Team"
        ]
        
        print("💡 Common organizational units:")
        for i, suggestion in enumerate(org_unit_suggestions, 1):
            print(f"   {i}. {suggestion}")
        print("   5. Enter custom")
        
        while True:
            choice = input(f"\n🏛️  Choose organizational unit (1-5): ").strip()
            if choice in ['1', '2', '3', '4']:
                org_unit = org_unit_suggestions[int(choice) - 1]
                break
            elif choice == '5':
                org_unit = self.get_user_input("🏛️  Enter organizational unit", "IT Department")
                break
            else:
                print("❌ Please choose 1-5!")
        
        # Get local TLDs
        print(f"\n🌐 Local Network Domains:")
        print("These TLDs will be used for domain suggestions:")
        
        default_tlds = example_config.get("defaults", {}).get("localTLDs", ["lan", "local", "fkn", "internal"]) if example_config else ["lan", "local", "fkn", "internal"]
        
        print("💡 Common local TLDs:")
        print("   1. lan, local, fkn, internal (recommended)")
        print("   2. lan, local (minimal)")  
        print("   3. home, lan, local, internal (extended)")
        print("   4. Custom selection")
        
        tld_options = [
            ["lan", "local", "fkn", "internal"],
            ["lan", "local"],
            ["home", "lan", "local", "internal"],
            []  # Custom
        ]
        
        while True:
            choice = input(f"\n🌐 Choose TLD set (1-4): ").strip()
            if choice in ['1', '2', '3']:
                local_tlds = tld_options[int(choice) - 1]
                break
            elif choice == '4':
                print("\n📝 Enter your local TLDs (comma-separated, e.g., 'lan,local,home'):")
                tld_input = input("🌐 TLDs: ").strip()
                if tld_input:
                    local_tlds = [tld.strip().lstrip('.') for tld in tld_input.split(',') if tld.strip()]
                    if local_tlds:
                        break
                    else:
                        print("❌ Please enter at least one TLD!")
                else:
                    local_tlds = default_tlds
                    break
            else:
                print("❌ Please choose 1-4!")
        
        print(f"✅ Selected TLDs: {', '.join(local_tlds)}")
        
        # Get certificate defaults
        print(f"\n🔐 Certificate Settings:")
        
        # Key size suggestions
        print("💡 Recommended key sizes:")
        print("   1. 2048 bits (standard, faster)")
        print("   2. 4096 bits (more secure, slower)")
        
        while True:
            choice = input(f"\n🔑 Choose key size (1-2): ").strip()
            if choice == '1':
                key_size = 2048
                break
            elif choice == '2':
                key_size = 4096
                break
            else:
                print("❌ Please choose 1-2!")
        
        # Validity period suggestions
        validity_options = [
            (365, "1 year (recommended for testing)"),
            (825, "2.25 years (modern browser limit)"), 
            (1095, "3 years (traditional)"),
            (3650, "10 years (internal use only)")
        ]
        
        print("💡 Certificate validity periods:")
        for i, (days, desc) in enumerate(validity_options, 1):
            print(f"   {i}. {desc}")
        
        while True:
            choice = input(f"\n📅 Choose validity period (1-4): ").strip()
            if choice in ['1', '2', '3', '4']:
                validity_days = validity_options[int(choice) - 1][0]
                break
            else:
                print("❌ Please choose 1-4!")
        
        # Create configuration
        config = {
            "ca": {
                "country": country.upper()[:2],
                "state": state,
                "city": city,
                "organization": user_name,
                "organizationalUnit": org_unit,
                "email": email,
                "commonName": ca_name
            },
            "defaults": {
                "keySize": key_size,
                "validityDays": validity_days,
                "country": country.upper()[:2],
                "state": state,
                "city": city,
                "organization": user_name,
                "organizationalUnit": org_unit,
                "email": email,
                "localTLDs": local_tlds
            }
        }
        
        # Show summary and confirm
        print(f"\n📋 Configuration Summary:")
        print("─" * 50)
        print(f"🏛️  CA Name: {ca_name}")
        print(f"🏢 Organization: {user_name}")
        print(f"🏛️  Department: {org_unit}")
        print(f"📍 Location: {city}, {state}, {country}")
        print(f"📧 Email: {email}")
        print(f"🔑 Key Size: {key_size} bits")
        print(f"📅 Validity: {validity_days} days")
        print(f"🌐 Local TLDs: {', '.join(local_tlds)}")
        print("─" * 50)
        
        confirm = input(f"\n❓ Save this configuration? [Y/n]: ").strip().lower()
        if confirm in ['n', 'no']:
            print("👋 Setup cancelled.")
            sys.exit(0)
        
        # Save configuration
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"✅ Configuration saved to {self.config_file}")
            print("\n🎉 Setup complete! You can now create certificates.")
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")
            sys.exit(1)
        
        return config

    def create_interactive_config(self):
        """Creates a new configuration through interactive inputs."""
        print("\n🔧 New service configuration")
        print("─" * 50)
        
        # Use global config as base
        base_config = self.global_config.copy() if self.global_config else {}
        
        print("📝 Please enter the data for this service:")
        print("   (Leave empty to use default values)\n")
        
        # CA configuration
        ca_config = base_config.get("ca", {})
        ca_config["organization"] = self.get_user_input(
            "🏢 Organization", ca_config.get("organization"))
        ca_config["organizationalUnit"] = self.get_user_input(
            "🏛️  Department", ca_config.get("organizationalUnit"))
        ca_config["country"] = self.get_user_input(
            "🌍 Country (2 letters)", ca_config.get("country"))
        ca_config["state"] = self.get_user_input(
            "🏞️  State/Province", ca_config.get("state"))
        ca_config["city"] = self.get_user_input(
            "🏙️  City", ca_config.get("city"))
        ca_config["email"] = self.get_user_input(
            "📧 Email", ca_config.get("email"))
        ca_config["commonName"] = self.get_user_input(
            "🔖 CA Name", ca_config.get("commonName", f"{ca_config['organization']} CA"))
        
        # Defaults
        defaults = base_config.get("defaults", {})
        key_size = self.get_user_input(
            "🔐 Key size (bits)", str(defaults.get("keySize", 2048)))
        validity = self.get_user_input(
            "📅 Validity (days)", str(defaults.get("validityDays", 365)))
        
        try:
            defaults["keySize"] = int(key_size)
            defaults["validityDays"] = int(validity)
        except ValueError:
            print("❌ Invalid numbers entered, using default values!")
        
        # Copy CA data to defaults
        for key in ["country", "state", "city", "organization", "organizationalUnit", "email"]:
            defaults[key] = ca_config[key]
        
        # Add localTLDs if not present
        if "localTLDs" not in defaults:
            defaults["localTLDs"] = self.global_config.get("defaults", {}).get("localTLDs", ["lan", "local", "fkn", "internal"]) if self.global_config else ["lan", "local", "fkn", "internal"]
        
        return {
            "ca": ca_config,
            "defaults": defaults,
            "domains": []  # For saved domain list
        }