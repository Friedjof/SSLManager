#!/usr/bin/env python3
"""
SSL Certificate Manager - Main Entry Point
A professional SSL certificate management toolkit for HOME USE ONLY.

⚠️  SECURITY NOTICE:
This tool is designed for home and internal network use only.
Keep this directory secure and protected - it contains sensitive cryptographic material!

- CA private keys can issue certificates for any domain
- Use strong passwords and encrypt your storage
- Never use for production or public-facing services
- Protect access to this directory with appropriate file permissions
"""

import argparse
import getpass
from pathlib import Path

from src.config_manager import ConfigManager
from src.certificate_authority import CertificateAuthority
from src.certificate_manager import CertificateManager
from src.service_manager import ServiceManager
from src.revocation_manager import RevocationManager
from src.backup_manager import BackupManager
import os


class SSLManager:
    """Main SSL Certificate Manager application."""
    
    def __init__(self, config_file="config.json"):
        self.config_manager = ConfigManager(config_file)
        self.ca = CertificateAuthority()
        self.cert_manager = CertificateManager()
        self.service_manager = ServiceManager()
        self.revocation_manager = RevocationManager()
        self.backup_manager = BackupManager()
        
        # Load global configuration
        self.global_config = self.config_manager.load_global_config()
        self.service_config = None
        
        # Secure existing private keys on startup
        self.secure_existing_keys()

    def secure_existing_keys(self):
        """Secures existing private key files by setting 600 permissions."""
        key_files_secured = []
        
        # Secure CA private key
        ca_key = Path(self.ca.ca_key_path)
        if ca_key.exists():
            try:
                current_mode = ca_key.stat().st_mode & 0o777
                if current_mode != 0o600:
                    os.chmod(ca_key, 0o600)
                    key_files_secured.append(str(ca_key))
            except OSError:
                pass  # Skip if we can't change permissions
        
        # Secure service private keys
        for service_dir in Path('.').iterdir():
            if service_dir.is_dir() and not service_dir.name.startswith('.') and service_dir.name not in ['src', '__pycache__', 'archive']:
                for key_file in service_dir.rglob("*.key"):
                    try:
                        current_mode = key_file.stat().st_mode & 0o777
                        if current_mode != 0o600:
                            os.chmod(key_file, 0o600)
                            key_files_secured.append(str(key_file))
                    except OSError:
                        pass  # Skip if we can't change permissions
        
        # Show summary if any keys were secured
        if key_files_secured and len(key_files_secured) > 0:
            print("🔒 Secured existing private key files:")
            for key_file in key_files_secured:
                print(f"   • {key_file}")
            print()

    def show_help(self):
        """Shows the help text."""
        print("""🔐 SSL Certificate Manager - Help

USAGE:
    python sslmanager.py [OPTIONS] [SERVICE_NAME]

OPTIONS:
    -h, --help              Show this help
    -l, --list              Show all certificates with expiration dates
    -s, --status            Alias for --list
    -n, --new SERVICE       Create new certificate for SERVICE
    -i, --info SERVICE      Show details for SERVICE certificate
    -r, --renew SERVICE     Renew certificate for SERVICE
    -d, --delete SERVICE    Delete SERVICE and all certificates
    --revoke SERVICE        Revoke certificate for SERVICE
    --ca-info               Show CA information
    --ca-renew              Renew CA certificate (archive old one)
    --crl                   Show Certificate Revocation List
    --crl-update            Update/regenerate CRL file
    --backup PATH           Create encrypted backup to PATH
    --restore PATH          Restore from encrypted backup at PATH
    --service SERVICE       Backup/restore specific service only

EXAMPLES:
    python sslmanager.py                    # Interactive mode
    python sslmanager.py -l                 # List all certificates
    python sslmanager.py --new proxy        # New certificate for 'proxy'
    python sslmanager.py --info proxy       # Details for 'proxy' certificate
    python sslmanager.py --renew proxy      # Renew 'proxy' certificate
    python sslmanager.py --delete proxy     # Delete 'proxy' service
    python sslmanager.py --revoke proxy     # Revoke 'proxy' certificate
    python sslmanager.py --ca-info          # Show CA information
    python sslmanager.py --ca-renew         # Renew CA certificate
    python sslmanager.py --crl              # Show Certificate Revocation List
    python sslmanager.py --crl-update       # Update/regenerate CRL file
    python sslmanager.py --backup backup.enc         # Create encrypted backup
    python sslmanager.py --restore backup.enc        # Restore from backup
    python sslmanager.py --backup backup.enc --service proxy  # Backup single service
""")

    def parse_args(self):
        """Parses the command line arguments."""
        parser = argparse.ArgumentParser(
            description='SSL Certificate Management Script',
            add_help=False  # Use custom help
        )
        
        parser.add_argument('-h', '--help', action='store_true',
                          help='Show this help')
        parser.add_argument('-l', '--list', action='store_true',
                          help='Show all certificates with expiration dates')
        parser.add_argument('-s', '--status', action='store_true',
                          help='Alias for --list')
        parser.add_argument('-n', '--new', type=str, metavar='SERVICE',
                          help='Create new certificate for SERVICE')
        parser.add_argument('-i', '--info', type=str, metavar='SERVICE',
                          help='Show details for SERVICE certificate')
        parser.add_argument('-r', '--renew', type=str, metavar='SERVICE',
                          help='Renew certificate for SERVICE')
        parser.add_argument('-d', '--delete', type=str, metavar='SERVICE',
                          help='Delete SERVICE and all certificates')
        parser.add_argument('--revoke', type=str, metavar='SERVICE',
                          help='Revoke certificate for SERVICE')
        parser.add_argument('--ca-info', action='store_true',
                          help='Show CA information')
        parser.add_argument('--ca-renew', action='store_true',
                          help='Renew CA certificate (archive old one)')
        parser.add_argument('--crl', action='store_true',
                          help='Show Certificate Revocation List')
        parser.add_argument('--crl-update', action='store_true',
                          help='Update/regenerate CRL file')
        parser.add_argument('--backup', type=str, metavar='PATH',
                          help='Create encrypted backup to PATH')
        parser.add_argument('--restore', type=str, metavar='PATH', 
                          help='Restore from encrypted backup at PATH')
        parser.add_argument('--service', type=str, metavar='SERVICE',
                          help='Backup/restore specific service only')
        
        return parser.parse_args()

    def create_new_service(self, service_name):
        """Creates a new certificate for the specified service."""
        print(f"🔐 Creating new certificate for service '{service_name}'")
        print("=" * 50)
        
        # Check CA files
        if not self.ca.check_ca_files():
            print("❌ CA files not found!")
            return False
        
        # Validate service name
        valid, error = self.service_manager.validate_service_name(service_name)
        if not valid:
            print(f"❌ {error}")
            return False
        
        # Check if service already exists and load config
        existing_services = self.service_manager.find_existing_services()
        service_path = Path(service_name)
        skip_domain_selection = False
        selected_domains = []
        
        if service_name in existing_services:
            existing_config = self.config_manager.load_service_config(service_path)
            if existing_config:
                self.service_config = existing_config
                if existing_config.get("domains"):
                    selected_domains = existing_config["domains"]
                    skip_domain_selection = True
                    print(f"✅ Using existing configuration and domains:")
                    for domain in selected_domains:
                        print(f"   • {domain}")
            else:
                self.service_config = self.config_manager.create_interactive_config()
        else:
            self.service_config = self.config_manager.create_interactive_config()
        
        # Domain selection if necessary
        if not skip_domain_selection:
            local_tlds = self.service_config.get("defaults", {}).get("localTLDs", ["lan", "fkn"])
            suggestions = self.cert_manager.suggest_domains(service_name, local_tlds)
            print("\n💡 Suggested domains:")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"   {i}️⃣  {suggestion}")
            
            domain_input = input("\n🎯 Domain selection (e.g. '1,3,custom.lan'): ").strip()
            if not domain_input:
                selected_domains = [suggestions[0]]  # Default: first suggestion
            else:
                selected_domains = self.cert_manager.parse_domain_input(domain_input, suggestions)
            
            self.service_config["domains"] = selected_domains
        
        # Save config
        if not self.config_manager.save_service_config(service_path, self.service_config):
            print("❌ Error saving configuration!")
            return False
        
        # Create certificate
        service_dir = self.cert_manager.create_directory(service_name)
        ca_password = getpass.getpass("🔐 CA password: ")
        
        key_path, cert_path, pem_path = self.cert_manager.create_server_cert(
            service_dir, selected_domains, ca_password, self.service_config)
        
        if key_path and cert_path and pem_path:
            print(f"\n✅ Certificate for '{service_name}' successfully created!")
            return True
        else:
            print(f"❌ Error creating certificate for '{service_name}'!")
            return False

    def run_interactive_mode(self):
        """Runs the interactive mode (certificate creation)."""
        print("🔐 SSL Certificate Manager")
        print("=" * 50)
        
        # Step 1: Check CA files first
        print("\n🔍 Checking CA files...")
        if not self.ca.check_ca_files():
            print("\n❓ No CA files found. Create a new CA?")
            choice = input("   [y]es / [n]o / [a]bort: ").strip().lower()
            
            if choice in ['a', 'abort']:
                print("👋 Process aborted.")
                return
            elif choice in ['y', 'yes']:
                print("\n🔧 Creating new Certificate Authority...")
                ca_password = getpass.getpass("🔐 Password for new CA: ")
                if not ca_password:
                    print("❌ CA password cannot be empty!")
                    return
                
                if not self.ca.create_new_ca(ca_password, self.global_config):
                    print("❌ Error creating CA!")
                    return
            else:
                print("❌ CA files are required! Please create a CA first.")
                return
        else:
            print("✅ CA files found!")
        
        # Step 2: Enter and validate service name
        while True:
            print("\n📝 Enter service name:")
            service_name = input("🏷️  Service: ").strip()
            
            valid, error = self.service_manager.validate_service_name(service_name)
            if valid:
                break
            print(f"❌ {error}")
        
        # Step 3: Check if service already exists
        existing_services = self.service_manager.find_existing_services()
        service_path = Path(service_name)
        skip_domain_selection = False
        selected_domains = []
        
        if service_name in existing_services:
            print(f"\n🔍 Service '{service_name}' already exists!")
            
            # Load existing configuration
            existing_config = self.config_manager.load_service_config(service_path)
            
            if existing_config:
                print(f"\n📋 Found configuration for '{service_name}':")
                self.config_manager.service_config = existing_config
                
                # Show saved domains
                if existing_config.get("domains"):
                    print(f"\n🌐 Saved domains:")
                    for i, domain in enumerate(existing_config["domains"], 1):
                        print(f"   {i}. {domain}")
                
                print("\n❓ Use this configuration and domains?")
                choice = input("   [y]es / [n]o / [a]bort: ").strip().lower()
                
                if choice in ['a', 'abort']:
                    print("👋 Process aborted.")
                    return
                elif choice in ['y', 'yes']:
                    self.service_config = existing_config
                    print("✅ Using existing configuration.")
                    # If domains are present, go directly to certificate creation
                    if existing_config.get("domains"):
                        selected_domains = existing_config["domains"]
                        print("✅ Using saved domains for certificate generation.")
                        skip_domain_selection = True
                    else:
                        skip_domain_selection = False
                else:
                    print("🔧 Creating new configuration...")
                    self.service_config = self.config_manager.create_interactive_config()
                    skip_domain_selection = False
            else:
                print(f"⚠️  No valid configuration found for '{service_name}'.")
                self.service_config = self.config_manager.create_interactive_config()
                skip_domain_selection = False
        else:
            print(f"\n🆕 Creating new service '{service_name}'.")
            self.service_config = self.config_manager.create_interactive_config()
            skip_domain_selection = False
        
        # Step 4: Domain selection (if not already loaded from config)
        if not skip_domain_selection:
            print("\n🌐 Domain configuration:")
            local_tlds = self.service_config.get("defaults", {}).get("localTLDs", ["lan", "fkn"])
            suggestions = self.cert_manager.suggest_domains(service_name, local_tlds)
            
            print("💡 Suggested domains:")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"   {i}️⃣  {suggestion}")
            
            print("\n📝 Enter your domain selection:")
            print("   • Separate multiple domains with commas: '1, 3, 4'")
            print("   • Mix numbers and custom domains: '1, 3, iot.lan, *.iot.fkn'")
            print("   • Or only custom domains: 'example.com, *.example.com'")
            
            while True:
                domain_input = input("\n🎯 Domain selection: ").strip()
                if not domain_input:
                    print("❌ Please enter at least one domain!")
                    continue
                
                selected_domains = self.cert_manager.parse_domain_input(domain_input, suggestions)
                if not selected_domains:
                    print("❌ No valid domains found!")
                    continue
                
                print(f"\n✅ Selected domains:")
                for i, domain in enumerate(selected_domains, 1):
                    print(f"   {i}. {domain}")
                
                confirm = input("\n❓ Confirm domains? [y/n]: ").strip().lower()
                if confirm in ['y', 'yes']:
                    break
                
            # Save domains in service config
            self.service_config["domains"] = selected_domains
            
        # Save service configuration with updated domains
        if not self.config_manager.save_service_config(service_path, self.service_config):
            print("❌ Error saving configuration!")
            return
        
        # Step 5: Create directory
        service_dir = self.cert_manager.create_directory(service_name)
        
        # Step 6: Enter CA password
        print("\n🔑 CA password:")
        ca_password = getpass.getpass("🔐 Password for CA key: ")
        if not ca_password:
            print("❌ CA password cannot be empty!")
            return
        
        # Step 7: Create server certificate for all domains
        print(f"\n🔨 Creating certificate for {len(selected_domains)} domain(s)...")
        for domain in selected_domains:
            print(f"   • {domain}")
        
        key_path, cert_path, pem_path = self.cert_manager.create_server_cert(
            service_dir, selected_domains, ca_password, self.service_config)
        
        if key_path and cert_path and pem_path:
            print("\n🎉 Certificate successfully created!")
            print("=" * 50)
            print(f"📂 Directory:      {service_dir}")
            print(f"🏛️  CA certificate:    {self.ca.ca_cert_path}")
            print(f"🔑 Server key:       {key_path}")
            print(f"📜 Server certificate: {cert_path}")
            print(f"📋 PEM file:        {pem_path}")
            print("=" * 50)
            print("\n💡 Next steps:")
            print("   1️⃣  Install CA certificate in browser/system")
            print("   2️⃣  Use cert.key and cert.crt in your application")
            print("   3️⃣  Or use cert.pem for combined certificate chain")
            print("   4️⃣  SSL warnings should now disappear")
        else:
            print("❌ Error creating certificate!")

    def main(self):
        """Main function - handles command line arguments."""
        args = self.parse_args()
        
        # Show help
        if args.help:
            self.show_help()
            return
        
        # Show certificate list
        if args.list or args.status:
            self.service_manager.scan_certificates(self.cert_manager)
            return
        
        # Create new certificate
        if args.new:
            self.create_new_service(args.new)
            return
        
        # Show service information
        if args.info:
            self.service_manager.show_service_info(args.info, self.cert_manager, self.config_manager)
            return
        
        # Renew certificate
        if args.renew:
            print(f"🔄 Renewing certificate for service '{args.renew}'...")
            self.create_new_service(args.renew)
            return
        
        # Delete service
        if args.delete:
            self.service_manager.delete_service(args.delete)
            return
        
        # Revoke certificate
        if args.revoke:
            self.revocation_manager.revoke_certificate(args.revoke)
            return
        
        # Show CA information
        if args.ca_info:
            self.ca.show_ca_info()
            return
        
        # Renew CA certificate
        if args.ca_renew:
            print("🔄 CA Certificate Renewal")
            print("=" * 50)
            ca_password = getpass.getpass("🔐 CA password: ")
            if not ca_password:
                print("❌ CA password cannot be empty!")
                return
            
            self.ca.renew_ca_certificate(ca_password, self.global_config)
            return
        
        # Show Certificate Revocation List
        if args.crl:
            self.revocation_manager.show_crl()
            return
        
        # Update Certificate Revocation List
        if args.crl_update:
            print("🔄 Updating Certificate Revocation List")
            print("=" * 50)
            ca_password = getpass.getpass("🔐 CA password: ")
            if not ca_password:
                print("❌ CA password cannot be empty!")
                return
            
            self.revocation_manager.update_crl(ca_password)
            return
        
        # Create backup
        if args.backup:
            self.backup_manager.create_backup(args.backup, args.service, self.service_manager)
            return
        
        # Restore backup
        if args.restore:
            self.backup_manager.restore_backup(args.restore, args.service)
            return
        
        # Default: Interactive mode
        self.run_interactive_mode()


if __name__ == "__main__":
    manager = SSLManager()
    manager.main()