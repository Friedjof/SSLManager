"""
Certificate Authority management for SSL Certificate Manager.
Handles CA creation, validation, and information display.
"""

import subprocess
from pathlib import Path
import getpass
import shutil
import os
from datetime import datetime


class CertificateAuthority:
    """Manages Certificate Authority operations."""
    
    def __init__(self, ca_cert_path="root-ca.crt", ca_key_path="root-ca.key"):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
    
    def check_ca_files(self):
        """Checks if the CA files exist."""
        ca_cert_exists = Path(self.ca_cert_path).exists()
        ca_key_exists = Path(self.ca_key_path).exists()
        
        if not ca_cert_exists:
            print(f"❌ CA certificate '{self.ca_cert_path}' not found!")
        if not ca_key_exists:
            print(f"❌ CA key '{self.ca_key_path}' not found!")
        
        return ca_cert_exists and ca_key_exists

    def create_new_ca(self, ca_password, service_config):
        """Creates a new Certificate Authority."""
        if not service_config:
            raise ValueError("Service configuration not loaded!")
        
        ca_key_path = Path(self.ca_key_path)
        ca_cert_path = Path(self.ca_cert_path)
        
        # Create CA private key (with password)
        ca_key_cmd = [
            "openssl", "genrsa", 
            "-aes256", 
            "-out", str(ca_key_path),
            "-passout", f"pass:{ca_password}",
            str(service_config["defaults"]["keySize"])
        ]
        
        # Create CA certificate
        ca_config = service_config["ca"]
        ca_subject = f"/C={ca_config['country']}/ST={ca_config['state']}/L={ca_config['city']}/O={ca_config['organization']}/OU={ca_config['organizationalUnit']}/CN={ca_config['commonName']}/emailAddress={ca_config['email']}"
        
        ca_cert_cmd = [
            "openssl", "req", "-new", "-x509",
            "-key", str(ca_key_path),
            "-out", str(ca_cert_path),
            "-days", "3650",
            "-subj", ca_subject,
            "-passin", f"pass:{ca_password}"
        ]
        
        try:
            print("🔨 Creating CA private key...")
            subprocess.run(ca_key_cmd, check=True, capture_output=True)
            
            # Set secure permissions on CA private key immediately
            os.chmod(self.ca_key_path, 0o600)
            print(f"🔒 Set secure permissions (600) on {self.ca_key_path}")
            
            print("🔨 Creating CA certificate...")
            subprocess.run(ca_cert_cmd, check=True, capture_output=True)
            print(f"✅ CA successfully created!")
            print(f"🔒 IMPORTANT: Protect your CA files - they can issue certificates for any domain!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Error creating CA: {e}")
            return False

    def get_ca_expiry_info(self):
        """Gets CA certificate expiration information."""
        if not Path(self.ca_cert_path).exists():
            return None, None, None, None
        
        try:
            # Get expiration date in specific format
            cmd = ["openssl", "x509", "-in", self.ca_cert_path, "-noout", "-enddate"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Parse the result (format: notAfter=MMM DD HH:MM:SS YYYY GMT)
            end_date_str = result.stdout.strip().replace("notAfter=", "")
            
            # Get days until expiration
            cmd_days = ["openssl", "x509", "-in", self.ca_cert_path, "-noout", "-checkend", "0"]
            days_result = subprocess.run(cmd_days, capture_output=True, text=True)
            
            # Calculate days remaining more precisely
            from datetime import datetime, timezone
            import time
            
            # Parse the date
            try:
                # Convert GMT time to timestamp
                end_time = time.strptime(end_date_str, "%b %d %H:%M:%S %Y %Z")
                end_timestamp = time.mktime(end_time)
                current_timestamp = time.time()
                
                days_remaining = int((end_timestamp - current_timestamp) / 86400)  # 86400 seconds in a day
                
                is_expired = days_remaining < 0
                expires_soon = days_remaining <= 30 and days_remaining > 0
                
                return end_date_str, days_remaining, is_expired, expires_soon
                
            except ValueError:
                return end_date_str, None, None, None
            
        except subprocess.CalledProcessError:
            return None, None, None, None

    def show_ca_info(self):
        """Shows information about the CA."""
        print("🏛️  Certificate Authority Information")
        print("=" * 50)
        
        if not self.check_ca_files():
            print("❌ CA files not found!")
            return
        
        try:
            # CA certificate information
            cmd = ["openssl", "x509", "-in", self.ca_cert_path, "-noout", "-text"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Extract important information
            lines = result.stdout.split('\n')
            
            print("📋 CA Certificate Details:")
            for line in lines:
                if "Subject:" in line:
                    print(f"   🏢 Subject: {line.split('Subject: ')[1]}")
                elif "Issuer:" in line:
                    print(f"   🏛️  Issuer: {line.split('Issuer: ')[1]}")
                elif "Not Before:" in line:
                    print(f"   📅 Valid from: {line.strip()}")
                elif "Not After:" in line:
                    print(f"   ⏰ Valid until: {line.strip()}")
            
            # Get expiration status
            end_date, days_remaining, is_expired, expires_soon = self.get_ca_expiry_info()
            if days_remaining is not None:
                if is_expired:
                    print(f"   ❌ Status: EXPIRED ({abs(days_remaining)} days ago)")
                elif expires_soon:
                    print(f"   ⚠️  Status: EXPIRES SOON ({days_remaining} days remaining)")
                else:
                    print(f"   ✅ Status: VALID ({days_remaining} days remaining)")
            
            print(f"\n📄 CA Files:")
            print(f"   🔑 Private Key: {self.ca_key_path}")
            print(f"   📜 Certificate: {self.ca_cert_path}")
            
            # Show renewal option if expired or expires soon
            if is_expired or expires_soon:
                print(f"\n💡 Tip: Use 'python sslmanager.py --ca-renew' to renew the CA certificate")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Error reading CA information: {e}")

    def archive_ca_files(self):
        """Archives the current CA files to archive directory."""
        archive_dir = Path("archive")
        archive_dir.mkdir(exist_ok=True)
        
        # Create timestamp for archive folder
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ca_archive_dir = archive_dir / f"ca_{timestamp}"
        ca_archive_dir.mkdir(exist_ok=True)
        
        archived_files = []
        
        # Archive CA certificate
        if Path(self.ca_cert_path).exists():
            archived_cert = ca_archive_dir / Path(self.ca_cert_path).name
            shutil.copy2(self.ca_cert_path, archived_cert)
            archived_files.append(str(archived_cert))
        
        # Archive CA private key
        if Path(self.ca_key_path).exists():
            archived_key = ca_archive_dir / Path(self.ca_key_path).name
            shutil.copy2(self.ca_key_path, archived_key)
            archived_files.append(str(archived_key))
        
        # Archive serial file if exists
        serial_file = Path("root-ca.srl")
        if serial_file.exists():
            archived_serial = ca_archive_dir / serial_file.name
            shutil.copy2(serial_file, archived_serial)
            archived_files.append(str(archived_serial))
        
        return ca_archive_dir, archived_files

    def renew_ca_certificate(self, ca_password, service_config):
        """Renews the CA certificate by archiving old one and creating new."""
        print("🔄 Renewing Certificate Authority...")
        print("=" * 50)
        
        # Check if current CA exists
        if not self.check_ca_files():
            print("❌ No existing CA found to renew!")
            return False
        
        # Get current CA expiry info
        end_date, days_remaining, is_expired, expires_soon = self.get_ca_expiry_info()
        
        if not is_expired and not expires_soon:
            print(f"⚠️  CA certificate is still valid for {days_remaining} days.")
            confirm = input("❓ Are you sure you want to renew it? [y/N]: ").strip().lower()
            if confirm not in ['y', 'yes']:
                print("👋 CA renewal cancelled.")
                return False
        
        # Archive current CA files
        print("\n📦 Archiving current CA files...")
        try:
            archive_dir, archived_files = self.archive_ca_files()
            print(f"✅ CA files archived to: {archive_dir}")
            for file in archived_files:
                print(f"   📄 {file}")
        except Exception as e:
            print(f"❌ Error archiving CA files: {e}")
            confirm = input("❓ Continue without archiving? [y/N]: ").strip().lower()
            if confirm not in ['y', 'yes']:
                return False
        
        # Remove old CA files
        print("\n🗑️  Removing old CA files...")
        try:
            if Path(self.ca_cert_path).exists():
                Path(self.ca_cert_path).unlink()
            if Path(self.ca_key_path).exists():
                Path(self.ca_key_path).unlink()
            if Path("root-ca.srl").exists():
                Path("root-ca.srl").unlink()
        except Exception as e:
            print(f"❌ Error removing old CA files: {e}")
            return False
        
        # Create new CA
        print("\n🔨 Creating new CA certificate...")
        success = self.create_new_ca(ca_password, service_config)
        
        if success:
            print("\n🎉 CA certificate successfully renewed!")
            print("=" * 50)
            print("📋 Next steps:")
            print("   1️⃣  All existing service certificates are still valid")
            print("   2️⃣  Install new CA certificate in browsers/systems")
            print("   3️⃣  Consider renewing service certificates for consistency")
            print("   4️⃣  Old CA files are safely archived")
            print("=" * 50)
        else:
            print("❌ Failed to create new CA!")
            print("💡 Old CA files are archived and can be restored if needed")
        
        return success