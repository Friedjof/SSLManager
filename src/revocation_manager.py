"""
Certificate revocation management for SSL Certificate Manager.
Handles certificate revocation and CRL (Certificate Revocation List) operations.
"""

import subprocess
from pathlib import Path
import getpass
import os
import tempfile


class RevocationManager:
    """Manages certificate revocation and CRL operations."""
    
    def __init__(self, ca_cert_path="root-ca.crt", ca_key_path="root-ca.key"):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.ca_index_file = "ca-index.txt"
        self.ca_serial_file = "ca-serial.txt"
        self.ca_crl_file = "ca.crl"
        self.ca_config_file = "ca.conf"
    
    def setup_ca_database(self):
        """Sets up the CA database files needed for proper CRL management."""
        # Create CA index file if it doesn't exist
        if not Path(self.ca_index_file).exists():
            Path(self.ca_index_file).touch()
            print(f"📄 Created CA database: {self.ca_index_file}")
        
        # Create CA serial file if it doesn't exist
        if not Path(self.ca_serial_file).exists():
            with open(self.ca_serial_file, 'w') as f:
                f.write("1000\n")
            print(f"📄 Created CA serial file: {self.ca_serial_file}")
        
        # Create CA config file for CRL operations
        self.create_ca_config()
    
    def create_ca_config(self):
        """Creates a temporary CA configuration file for CRL operations."""
        ca_config_content = f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
certs             = .
crl_dir           = .
database          = {self.ca_index_file}
new_certs_dir     = .
certificate       = {self.ca_cert_path}
serial            = {self.ca_serial_file}
crlnumber         = crlnumber.txt
crl               = {self.ca_crl_file}
private_key       = {self.ca_key_path}
default_days      = 365
default_crl_days  = 30
default_md        = sha256
preserve          = no
policy            = policy_loose
copy_extensions   = copy

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
"""
        
        with open(self.ca_config_file, 'w') as f:
            f.write(ca_config_content.strip())

    def revoke_certificate(self, service_name):
        """Revokes a certificate and adds it to the CRL."""
        service_path = Path(service_name)
        if not service_path.exists():
            print(f"❌ Service '{service_name}' not found!")
            return False
        
        # Find newest certificate
        year_dirs = [d for d in service_path.iterdir() if d.is_dir() and d.name.isdigit()]
        if not year_dirs:
            print(f"❌ No certificates found for service '{service_name}'!")
            return False
        
        latest_year_dir = max(year_dirs, key=lambda x: int(x.name))
        cert_path = latest_year_dir / "cert.crt"
        
        if not cert_path.exists():
            print(f"❌ Certificate for service '{service_name}' not found!")
            return False
        
        print(f"🚫 Revoking certificate for service '{service_name}'...")
        
        # Setup CA database
        self.setup_ca_database()
        
        # Request CA password
        ca_password = getpass.getpass("🔐 CA password: ")
        if not ca_password:
            print("❌ CA password is required!")
            return False
        
        try:
            # Extract serial number of certificate for logging
            serial_cmd = ["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"]
            serial_result = subprocess.run(serial_cmd, capture_output=True, text=True, check=True)
            serial_number = serial_result.stdout.strip().replace('serial=', '')
            
            # Check if certificate is already revoked
            if self.is_certificate_revoked(serial_number):
                print(f"⚠️  Certificate is already revoked!")
                print(f"📋 Serial number: {serial_number}")
                return False
            
            # Add certificate to CA database if not already there
            self.add_certificate_to_database(cert_path)
            
            # Revoke the certificate using OpenSSL CA command
            revoke_cmd = [
                "openssl", "ca",
                "-config", self.ca_config_file,
                "-revoke", str(cert_path),
                "-passin", f"pass:{ca_password}"
            ]
            
            result = subprocess.run(revoke_cmd, capture_output=True, text=True, check=True)
            
            # Generate new CRL
            self.generate_crl(ca_password)
            
            print(f"✅ Certificate for '{service_name}' successfully revoked!")
            print(f"📋 Serial number: {serial_number}")
            print(f"🗂️  Certificate added to CRL: {self.ca_crl_file}")
            print("💡 The certificate is now officially revoked and will be rejected by CRL-aware clients.")
            return True
            
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.decode() if e.stderr else str(e)
            print(f"❌ Error revoking certificate: {error_output}")
            return False
        finally:
            # Clean up temporary config file
            if Path(self.ca_config_file).exists():
                Path(self.ca_config_file).unlink()

    def add_certificate_to_database(self, cert_path):
        """Adds a certificate to the CA database if not already present."""
        # Extract certificate information
        subject_cmd = ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-nameopt", "RFC2253"]
        subject_result = subprocess.run(subject_cmd, capture_output=True, text=True, check=True)
        subject = subject_result.stdout.strip().replace('subject=', '')
        
        serial_cmd = ["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"]
        serial_result = subprocess.run(serial_cmd, capture_output=True, text=True, check=True)
        serial = serial_result.stdout.strip().replace('serial=', '')
        
        # Check if certificate is already in database
        if Path(self.ca_index_file).exists():
            with open(self.ca_index_file, 'r') as f:
                content = f.read()
                if serial in content:
                    return  # Already in database
        
        # Add certificate to database
        # Format: status<tab>expiration_date<tab>revocation_date<tab>serial<tab>unknown<tab>subject
        # Status: V = valid, R = revoked, E = expired
        
        # Get expiration date
        enddate_cmd = ["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"]
        enddate_result = subprocess.run(enddate_cmd, capture_output=True, text=True, check=True)
        enddate_str = enddate_result.stdout.strip().replace('notAfter=', '')
        
        # Convert to YYMMDDHHmmSSZ format
        from datetime import datetime
        import time
        end_time = time.strptime(enddate_str, "%b %d %H:%M:%S %Y %Z")
        expiry_date = datetime(*end_time[:6]).strftime("%y%m%d%H%M%SZ")
        
        # Add to database
        with open(self.ca_index_file, 'a') as f:
            f.write(f"V\t{expiry_date}\t\t{serial}\tunknown\t{subject}\n")

    def is_certificate_revoked(self, serial_number):
        """Checks if a certificate is already revoked."""
        if not Path(self.ca_index_file).exists():
            return False
        
        with open(self.ca_index_file, 'r') as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 4 and parts[0] == 'R' and parts[3] == serial_number:
                    return True
        return False

    def generate_crl(self, ca_password):
        """Generates a new Certificate Revocation List."""
        # Create CRL number file if it doesn't exist
        crl_number_file = "crlnumber.txt"
        if not Path(crl_number_file).exists():
            with open(crl_number_file, 'w') as f:
                f.write("1000\n")
        
        # Generate CRL
        crl_cmd = [
            "openssl", "ca",
            "-config", self.ca_config_file,
            "-gencrl",
            "-out", self.ca_crl_file,
            "-passin", f"pass:{ca_password}"
        ]
        
        subprocess.run(crl_cmd, capture_output=True, text=True, check=True)

    def show_crl(self):
        """Shows the Certificate Revocation List."""
        print("🚫 Certificate Revocation List")
        print("=" * 50)
        
        if not Path(self.ca_crl_file).exists():
            print("📄 No CRL file found. Revoke a certificate first to create one.")
            return
        
        try:
            # Show CRL information
            crl_cmd = ["openssl", "crl", "-in", self.ca_crl_file, "-noout", "-text"]
            result = subprocess.run(crl_cmd, capture_output=True, text=True, check=True)
            
            lines = result.stdout.split('\n')
            revoked_certs = []
            collecting_revoked = False
            
            print("📋 CRL Information:")
            for line in lines:
                if "Last Update:" in line:
                    print(f"   📅 {line.strip()}")
                elif "Next Update:" in line:
                    print(f"   📅 {line.strip()}")
                elif "Revoked Certificates:" in line:
                    collecting_revoked = True
                    continue
                elif collecting_revoked and "Serial Number:" in line:
                    serial = line.strip().replace('Serial Number: ', '')
                    revoked_certs.append(serial)
                elif collecting_revoked and "Revocation Date:" in line:
                    revocation_date = line.strip().replace('Revocation Date: ', '')
                    if revoked_certs:
                        print(f"   🚫 Serial: {revoked_certs[-1]} | Revoked: {revocation_date}")
            
            if not revoked_certs:
                print("✅ No certificates are currently revoked.")
            else:
                print(f"\n📊 Total revoked certificates: {len(revoked_certs)}")
                print(f"📁 CRL file: {self.ca_crl_file}")
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Error reading CRL: {e}")

    def update_crl(self, ca_password):
        """Updates the Certificate Revocation List (legacy method for compatibility)."""
        self.setup_ca_database()
        try:
            self.create_ca_config()
            self.generate_crl(ca_password)
            print("✅ CRL updated successfully.")
        except subprocess.CalledProcessError as e:
            print(f"❌ Error updating CRL: {e}")
        finally:
            if Path(self.ca_config_file).exists():
                Path(self.ca_config_file).unlink()