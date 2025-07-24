#!/usr/bin/env python3
"""
SSL Certificate Manager - Migration Script
Migrates old manual certificate structure to new automated structure.

⚠️  MIGRATION NOTICE:
This script converts old manual certificates to the new SSL Manager format.
OLD: <service>/<year>/cert.(crt|key|ext|csr)
NEW: <service>/<year>/cert.(crt|key|pem) + <service>/config.json

🔍 What this script does:
- Scans for old certificate structure
- Extracts domains from .ext files
- Creates service config.json files
- Creates .pem files (cert + CA chain)
- Preserves all existing files
- Generates migration report
"""

import json
import sys
import re
import shutil
from pathlib import Path
from datetime import datetime
import configparser
import subprocess
import os

class CertificateMigrator:
    """Migrates old certificate structure to new format."""
    
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.global_config = None
        self.migration_report = []
        self.ca_cert_path = "root-ca.crt"
        
        # Reserved directories that should not be treated as services
        self.reserved_names = {
            'src', '__pycache__', '.git', '.vscode', '.idea', 
            'node_modules', 'venv', 'env', '.env', 'dist', 'build',
            'archive', '.gitignore', 'LICENSE', 'README.md'
        }

    def load_global_config(self):
        """Loads the global configuration."""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.global_config = json.load(f)
                return True
        except FileNotFoundError:
            print(f"❌ Global config file '{self.config_file}' not found!")
            print("💡 Run 'python sslmanager.py' first to create the global configuration.")
            return False
        except json.JSONDecodeError:
            print(f"❌ Error reading configuration file {self.config_file}!")
            return False

    def scan_old_structure(self):
        """Scans for services with old certificate structure."""
        services_found = []
        current_dir = Path('.')
        
        for item in current_dir.iterdir():
            if (item.is_dir() and 
                item.name not in self.reserved_names and
                not item.name.startswith('.')):
                
                # Check if this looks like a service directory
                year_dirs = [d for d in item.iterdir() 
                           if d.is_dir() and d.name.isdigit()]
                
                if year_dirs:
                    # Check if any year directory has old certificate files
                    has_old_structure = False
                    certificates = []
                    
                    for year_dir in year_dirs:
                        cert_files = {
                            'crt': year_dir / 'cert.crt',
                            'key': year_dir / 'cert.key',
                            'ext': year_dir / 'cert.ext',
                            'csr': year_dir / 'cert.csr'
                        }
                        
                        # Check if this has old structure (has .ext file)
                        if cert_files['ext'].exists():
                            has_old_structure = True
                            certificates.append({
                                'year': year_dir.name,
                                'path': year_dir,
                                'files': {k: v for k, v in cert_files.items() if v.exists()}
                            })
                    
                    if has_old_structure:
                        services_found.append({
                            'name': item.name,
                            'path': item,
                            'certificates': certificates,
                            'has_config': (item / 'config.json').exists()
                        })
        
        return services_found

    def extract_domains_from_ext_file(self, ext_file_path):
        domains = set()

        try:
            with open(ext_file_path, 'r') as f:
                raw_content = f.read()

            # Trick: prepend fake [global] section so configparser can parse the top
            config_content = "[global]\n" + raw_content

            config = configparser.ConfigParser(strict=False, delimiters=('='))
            config.optionxform = str  # preserve case (important for 'DNS.x')
            config.read_string(config_content)

            # Try inline subjectAltName in [global] section
            if 'subjectAltName' in config['global']:
                san_value = config['global']['subjectAltName'].strip()

                # Case 1: subjectAltName = DNS:...
                if not san_value.startswith('@'):
                    entries = [e.strip() for e in san_value.split(',')]
                    for entry in entries:
                        if entry.startswith('DNS:'):
                            domains.add(entry.replace('DNS:', '').strip())

                # Case 2: subjectAltName = @alt_names
                else:
                    section_name = san_value[1:].strip()
                    if section_name in config:
                        for key, value in config[section_name].items():
                            if key.startswith('DNS.'):
                                domains.add(value.split('#')[0].strip())

            # Fallback: check for CN in raw text
            if not domains:
                subject_match = re.search(r'CN\s*=\s*([^,\n]+)', raw_content)
                if subject_match:
                    domains.add(subject_match.group(1).strip())

        except Exception as e:
            print(f"   ⚠️  Could not read {ext_file_path}: {e}")

        return sorted(domains)


    def extract_cert_info(self, cert_path):
        """Extracts information from certificate file."""
        cert_info = {}
        
        try:
            # Get subject information
            subject_cmd = ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"]
            result = subprocess.run(subject_cmd, capture_output=True, text=True, check=True)
            subject = result.stdout.strip()
            
            # Parse subject components
            subject_parts = {}
            for part in subject.replace('subject=', '').split('/' if '/' in subject else ','):
                if '=' in part:
                    key, value = part.split('=', 1)
                    subject_parts[key.strip()] = value.strip()
            
            cert_info['subject'] = subject_parts
            
            # Get dates
            dates_cmd = ["openssl", "x509", "-in", str(cert_path), "-noout", "-dates"]
            result = subprocess.run(dates_cmd, capture_output=True, text=True, check=True)
            dates = result.stdout.strip()
            
            for line in dates.split('\n'):
                if 'notBefore=' in line:
                    cert_info['not_before'] = line.replace('notBefore=', '')
                elif 'notAfter=' in line:
                    cert_info['not_after'] = line.replace('notAfter=', '')
            
        except subprocess.CalledProcessError as e:
            print(f"   ⚠️  Could not read certificate info: {e}")
        
        return cert_info

    def create_service_config(self, service_name, domains, cert_info):
        """Creates a service configuration based on extracted information."""
        print(f"   📄 Creating config for service '{service_name}'")
        # Base config from global config
        global_config = self.global_config or {}
        config = {
            "ca": global_config.get("ca", {}).copy(),
            "defaults": global_config.get("defaults", {}).copy(),
            "domains": domains,
            "migrated": {
                "date": datetime.now().isoformat(),
                "from": "manual_structure",
                "original_cert_info": cert_info
            }
        }
        
        # Update with certificate-specific information if available
        if cert_info.get('subject'):
            subject = cert_info['subject']
            if 'O' in subject:
                config['defaults']['organization'] = subject['O']
            if 'OU' in subject:
                config['defaults']['organizationalUnit'] = subject['OU']
            if 'C' in subject:
                config['defaults']['country'] = subject['C']
            if 'ST' in subject:
                config['defaults']['state'] = subject['ST']
            if 'L' in subject:
                config['defaults']['city'] = subject['L']
            if 'emailAddress' in subject:
                config['defaults']['email'] = subject['emailAddress']
        
        return config

    def create_pem_file(self, cert_path, pem_path):
        """Creates PEM file by combining certificate and CA."""
        try:
            with open(pem_path, 'w') as pem_file:
                # First the server certificate
                with open(cert_path, 'r') as cert_file:
                    pem_file.write(cert_file.read())
                
                # Then the CA certificate if it exists
                if Path(self.ca_cert_path).exists():
                    with open(self.ca_cert_path, 'r') as ca_file:
                        pem_file.write(ca_file.read())
            
            return True
        except Exception as e:
            print(f"   ⚠️  Could not create PEM file: {e}")
            return False

    def migrate_service(self, service):
        """Migrates a single service to the new structure."""
        service_name = service['name']
        service_path = service['path']
        
        print(f"\n📦 Migrating service: {service_name}")
        print("─" * 50)
        
        # Process each certificate year
        for cert in service['certificates']:
            year = cert['year']
            year_path = cert['path']
            files = cert['files']
            
            print(f"📅 Processing year: {year}")
            
            # Extract domains from .ext file
            domains = []
            if 'ext' in files:
                domains = self.extract_domains_from_ext_file(files['ext'])
                print(f"   🌐 Extracted domains: {', '.join(domains) if domains else 'None found'}")
            
            # Extract certificate info
            cert_info = {}
            if 'crt' in files:
                cert_info = self.extract_cert_info(files['crt'])
            
            # Create PEM file if not exists
            pem_path = year_path / 'cert.pem'
            if not pem_path.exists() and 'crt' in files:
                print(f"   📋 Creating PEM file...")
                if self.create_pem_file(files['crt'], pem_path):
                    print(f"   ✅ Created: {pem_path}")
                else:
                    print(f"   ❌ Failed to create PEM file")
            else:
                print(f"   ✅ PEM file already exists")
            
            # Set secure permissions on private key
            if 'key' in files:
                try:
                    current_mode = files['key'].stat().st_mode & 0o777
                    if current_mode != 0o600:
                        os.chmod(files['key'], 0o600)
                        print(f"   🔒 Secured private key permissions")
                    else:
                        print(f"   🔒 Private key already secure")
                except OSError:
                    print(f"   ⚠️  Could not set private key permissions")
        
        # Create or update service config.json
        config_path = service_path / 'config.json'
        
        # Use domains from the most recent certificate
        latest_cert = max(service['certificates'], key=lambda c: int(c['year']))
        latest_domains = []
        if 'ext' in latest_cert['files']:
            latest_domains = self.extract_domains_from_ext_file(latest_cert['files']['ext'])
        
        latest_cert_info = {}
        if 'crt' in latest_cert['files']:
            latest_cert_info = self.extract_cert_info(latest_cert['files']['crt'])
        
        if config_path.exists() and not service['has_config']:
            print(f"   ⚠️  Config file already exists, skipping creation")
        else:
            config = self.create_service_config(service_name, latest_domains, latest_cert_info)
            
            try:
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, ensure_ascii=False)
                print(f"   ✅ Created config: {config_path}")
            except Exception as e:
                print(f"   ❌ Failed to create config: {e}")
                return False
        
        # Add to migration report
        self.migration_report.append({
            'service': service_name,
            'certificates': len(service['certificates']),
            'domains': latest_domains,
            'years': [c['year'] for c in service['certificates']],
            'status': 'success'
        })
        
        print(f"   ✅ Service '{service_name}' migrated successfully")
        return True

    def run_migration(self):
        """Runs the complete migration process."""
        print("🔄 SSL Certificate Structure Migration")
        print("=" * 60)
        
        # Load global config
        if not self.load_global_config():
            return False
        
        print("✅ Global configuration loaded")
        
        # Scan for old structure
        print("\n🔍 Scanning for services with old certificate structure...")
        services = self.scan_old_structure()
        
        if not services:
            print("✅ No services found with old structure to migrate.")
            print("💡 All services are already using the new structure or no services found.")
            return True
        
        print(f"📋 Found {len(services)} service(s) to migrate:")
        for service in services:
            cert_count = len(service['certificates'])
            years = [c['year'] for c in service['certificates']]
            config_status = "✅ has config" if service['has_config'] else "❌ needs config"
            print(f"   • {service['name']}: {cert_count} certificate(s) in years {', '.join(years)} ({config_status})")
        
        # Confirm migration
        print(f"\n❓ Proceed with migration? This will:")
        print("   • Extract domains from .ext files")
        print("   • Create config.json for each service")
        print("   • Create .pem files (cert + CA chain)")
        print("   • Set secure permissions on private keys")
        print("   • Preserve all existing files")
        
        confirm = input("\n❓ Continue with migration? [Y/n]: ").strip().lower()
        if confirm in ['n', 'no']:
            print("👋 Migration cancelled.")
            return False
        
        # Perform migration
        print(f"\n🚀 Starting migration...")
        success_count = 0
        
        for service in services:
            try:
                if self.migrate_service(service):
                    success_count += 1
            except Exception as e:
                print(f"   ❌ Migration failed: {e}")
                self.migration_report.append({
                    'service': service['name'],
                    'status': 'error',
                    'error': str(e)
                })
        
        # Migration summary
        print(f"\n🎉 Migration completed!")
        print("=" * 60)
        print(f"✅ Successfully migrated: {success_count}/{len(services)} services")
        
        if self.migration_report:
            print(f"\n📋 Migration Report:")
            for report in self.migration_report:
                if report['status'] == 'success':
                    print(f"   ✅ {report['service']}: {report['certificates']} cert(s), {len(report['domains'])} domain(s)")
                    if report['domains']:
                        print(f"      🌐 Domains: {', '.join(report['domains'])}")
                else:
                    print(f"   ❌ {report['service']}: {report.get('error', 'Unknown error')}")
        
        print(f"\n💡 Next steps:")
        print("   1️⃣  Test the migrated services with 'python sslmanager.py --list'")
        print("   2️⃣  Verify domain configurations in service config.json files")
        print("   3️⃣  Old .ext and .csr files are preserved for reference")
        print("   4️⃣  You can now use 'python sslmanager.py --renew <service>' to update certificates")
        
        return success_count == len(services)


def main():
    """Main function."""
    migrator = CertificateMigrator()
    
    try:
        success = migrator.run_migration()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n👋 Migration cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
