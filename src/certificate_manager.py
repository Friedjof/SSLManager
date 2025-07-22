"""
Certificate management for SSL Certificate Manager.
Handles certificate creation, renewal, and domain configuration.
"""

import subprocess
from pathlib import Path
from datetime import datetime
import re
import os


class CertificateManager:
    """Manages SSL certificate operations."""
    
    def __init__(self, ca_cert_path="root-ca.crt", ca_key_path="root-ca.key"):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.year = datetime.now().year
    
    def create_directory(self, service_name):
        """Creates the directory for the service."""
        service_dir = Path(f"./{service_name}/{self.year}")
        service_dir.mkdir(parents=True, exist_ok=True)
        return service_dir

    def suggest_domains(self, service_name, local_tlds=None):
        """Suggests domain names based on the service name and configured TLDs."""
        if not local_tlds:
            local_tlds = ["lan", "fkn"]  # Default fallback
        
        suggestions = []
        for tld in local_tlds:
            suggestions.extend([
                f"{service_name}.{tld}",
                f"*.{service_name}.{tld}"
            ])
        
        return suggestions

    def parse_domain_input(self, input_str, suggestions):
        """Parses the domain input and returns a list of domains."""
        if not input_str.strip():
            return []
        
        domains = []
        parts = [part.strip() for part in input_str.split(',')]
        
        for part in parts:
            if not part:
                continue
                
            # Check if it's a number (suggestion)
            if part.isdigit():
                num = int(part)
                if 1 <= num <= len(suggestions):
                    domains.append(suggestions[num - 1])
                else:
                    print(f"⚠️  Invalid selection: {num} (ignored)")
            else:
                # Treat as custom domain
                domains.append(part)
        
        return list(set(domains))  # Remove duplicates

    def create_server_cert(self, service_dir, domains, ca_password, service_config):
        """Creates a server certificate for multiple domains."""
        if not service_config:
            raise ValueError("Service configuration not loaded!")
        
        # Use first domain as CN
        primary_domain = domains[0] if isinstance(domains, list) else domains
        
        key_path = service_dir / "cert.key"
        csr_path = service_dir / "cert.csr"
        cert_path = service_dir / "cert.crt"
        pem_path = service_dir / "cert.pem"
        
        # Create server private key
        server_key_cmd = [
            "openssl", "genrsa",
            "-out", str(key_path),
            str(service_config["defaults"]["keySize"])
        ]
        
        # Create Certificate Signing Request
        defaults = service_config["defaults"]
        server_subject = f"/C={defaults['country']}/ST={defaults['state']}/L={defaults['city']}/O={defaults['organization']}/OU={defaults['organizationalUnit']}/CN={primary_domain}/emailAddress={defaults['email']}"
        
        csr_cmd = [
            "openssl", "req", "-new",
            "-key", str(key_path),
            "-out", str(csr_path),
            "-subj", server_subject
        ]
        
        # SAN (Subject Alternative Names) extension for all domains
        san_extension = self.create_san_extension(domains)
        ext_file = service_dir / "cert.ext"
        
        with open(ext_file, 'w') as f:
            f.write(san_extension)
        
        # Sign certificate
        sign_cmd = [
            "openssl", "x509", "-req",
            "-in", str(csr_path),
            "-CA", self.ca_cert_path,
            "-CAkey", self.ca_key_path,
            "-CAcreateserial",
            "-out", str(cert_path),
            "-days", str(service_config["defaults"]["validityDays"]),
            "-extensions", "v3_req",
            "-extfile", str(ext_file),
            "-passin", f"pass:{ca_password}"
        ]
        
        try:
            print(f"🔨 Creating private key...")
            subprocess.run(server_key_cmd, check=True, capture_output=True)
            
            # Set secure permissions on server private key immediately
            os.chmod(key_path, 0o600)
            print(f"🔒 Set secure permissions (600) on {key_path}")
            
            print(f"🔨 Creating certificate request...")
            subprocess.run(csr_cmd, check=True, capture_output=True)
            
            print(f"🔨 Signing certificate...")
            subprocess.run(sign_cmd, check=True, capture_output=True)
            
            # Create PEM file (combined cert.crt + CA)
            print(f"🔨 Creating PEM file...")
            with open(pem_path, 'w') as pem_file:
                # First the server certificate
                with open(cert_path, 'r') as cert_file:
                    pem_file.write(cert_file.read())
                # Then the CA certificate
                with open(self.ca_cert_path, 'r') as ca_file:
                    pem_file.write(ca_file.read())
            
            # Clean up CSR and extension file (no longer needed)
            csr_path.unlink()
            ext_file.unlink()
            
            print(f"✅ Multi-domain certificate successfully created!")
            return key_path, cert_path, pem_path
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Error creating multi-domain certificate: {e}")
            return None, None, None

    def create_san_extension(self, domains):
        """Creates the SAN extension for multiple domains."""
        if isinstance(domains, str):
            domains = [domains]
        
        san_entries = []
        ip_entries = set()
        
        for domain in domains:
            # Add primary domain
            san_entries.append(f"DNS:{domain}")
            
            # Automatically add www variant (if not already present and not wildcard)
            if not domain.startswith("www.") and not domain.startswith("*.") and not any(d.startswith("www.") for d in domains):
                san_entries.append(f"DNS:www.{domain}")
            
            # For .lan and .local domains also add IP addresses
            if domain.endswith(('.lan', '.local')):
                ip_entries.add("IP:127.0.0.1")
                ip_entries.add("IP:::1")
        
        # Add IP addresses to SAN
        san_entries.extend(sorted(ip_entries))
        
        # Remove duplicates and sort
        san_entries = sorted(list(set(san_entries)))
        san_line = "subjectAltName = " + ", ".join(san_entries)
        
        extension = f"""[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
{san_line}
"""
        return extension

    def parse_certificate_dates(self, cert_path):
        """Extracts validity dates from a certificate."""
        try:
            # Use OpenSSL to read certificate data
            cmd = ["openssl", "x509", "-in", str(cert_path), "-noout", "-dates"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            dates = {}
            for line in result.stdout.strip().split('\n'):
                if line.startswith('notBefore='):
                    date_str = line.replace('notBefore=', '')
                    dates['issued'] = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                elif line.startswith('notAfter='):
                    date_str = line.replace('notAfter=', '')
                    dates['expires'] = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
            
            return dates
        except (subprocess.CalledProcessError, ValueError) as e:
            print(f"⚠️  Error reading {cert_path}: {e}")
            return None