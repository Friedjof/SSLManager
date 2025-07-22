# SSL Certificate Manager

A comprehensive Python-based SSL certificate management tool that creates a private Certificate Authority (CA) and issues SSL certificates for multiple domains.

## Features

🔐 **Private CA Management**
- Create and manage your own Certificate Authority
- Password-protected CA private keys
- CA information display and validation

📋 **Multi-Domain Certificates**
- Support for multiple domains in a single certificate
- Wildcard domain support (*.example.com)
- Automatic SAN (Subject Alternative Names) configuration
- Support for local domains (.lan, .local) with IP addresses

🏗️ **Service-Based Organization**
- Organize certificates by service name
- Yearly directory structure for easy management
- Configuration persistence and reuse
- Service-specific domain management

⚡ **Command Line Interface**
- Interactive mode for guided certificate creation
- Direct command execution for automation
- Comprehensive certificate status overview
- Certificate renewal and revocation support

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ssl-certificate-manager
```

2. Ensure OpenSSL is installed on your system:
```bash
# Ubuntu/Debian
sudo apt install openssl

# CentOS/RHEL
sudo yum install openssl

# macOS
brew install openssl
```

3. The tool will automatically set up configuration on first run. You can optionally create a template:
```bash
cp config.json.example config.json
```

Or let the interactive setup wizard guide you through configuration. The wizard will use `config.json.example` as defaults if available.
```json
{
  "ca": {
    "country": "US",
    "state": "California", 
    "city": "San Francisco",
    "organization": "Your Organization",
    "organizationalUnit": "IT Department",
    "email": "admin@example.com",
    "commonName": "Your Root CA"
  },
  "defaults": {
    "keySize": 2048,
    "validityDays": 365,
    "country": "US",
    "state": "California",
    "city": "San Francisco", 
    "organization": "Your Organization",
    "organizationalUnit": "IT Department",
    "email": "ssl@example.com",
    "localTLDs": ["lan", "local", "fkn", "internal"]
  }
}
```

## Usage

### First-Time Setup
When you run the tool for the first time, it will automatically start the setup wizard:

```bash
python ssl.py
```

The setup wizard will guide you through:
- **Organization Details**: Your name/company, location, contact info
- **CA Configuration**: Certificate Authority naming and setup
- **Local Network Domains**: Configure TLDs for domain suggestions (e.g., .lan, .local, .fkn)
- **Certificate Settings**: Key sizes, validity periods, and defaults

The wizard will:
- Use `config.json.example` as template if available
- Suggest realistic values based on your input
- Provide multiple choice options for common settings
- Show a summary before saving

### Interactive Mode
After setup, running without arguments starts interactive certificate creation:
```bash
python ssl.py
```

### Command Line Options

#### Certificate Management
```bash
# Create new certificate for a service
python ssl.py --new proxy

# List all certificates with expiration dates
python ssl.py --list
python ssl.py -l

# Show detailed service information
python ssl.py --info proxy

# Renew a certificate
python ssl.py --renew proxy

# Delete a service and all certificates
python ssl.py --delete proxy
```

#### Certificate Revocation
```bash
# Revoke a certificate
python ssl.py --revoke proxy

# Show Certificate Revocation List
python ssl.py --crl
```

#### CA Management
```bash
# Show CA information (including expiration status)
python ssl.py --ca-info

# Renew CA certificate (archives old one)
python ssl.py --ca-renew

# Show help
python ssl.py --help
```

## Directory Structure

```
ssl-certificate-manager/
├── ssl.py                  # Main entry point
├── src/                    # Source code modules
│   ├── __init__.py
│   ├── config_manager.py   # Configuration management
│   ├── certificate_authority.py  # CA operations
│   ├── certificate_manager.py    # Certificate operations
│   ├── service_manager.py  # Service operations
│   ├── revocation_manager.py     # Certificate revocation
│   └── backup_manager.py   # Backup and restore
├── config.json            # Global configuration
├── root-ca.crt            # CA certificate
├── root-ca.key            # CA private key
├── revoked_serials.txt    # Revoked certificate serials
├── archive/                # Archived CA certificates
│   └── ca_YYYYMMDD_HHMMSS/ # Timestamped CA backups
│       ├── root-ca.crt     # Archived CA certificate
│       ├── root-ca.key     # Archived CA private key
│       └── root-ca.srl     # Archived serial file
└── <service-name>/        # Service directories
    ├── config.json        # Service-specific config
    └── <year>/           # Yearly certificate storage
        ├── cert.crt      # Server certificate
        ├── cert.key      # Server private key
        └── cert.pem      # Combined certificate chain
```

## Domain Configuration

When creating certificates, you can specify domains in several ways:

### Using Suggestions
The tool suggests common patterns based on your service name and configured local TLDs (configurable in global config.json):
- `service.lan` 
- `*.service.lan`
- `service.local`
- `*.service.local`
- etc. (based on your localTLDs configuration)

### Multiple Domain Input
You can specify multiple domains using comma-separated values:
```
# Mix of suggestions and custom domains
1, 3, custom.lan, *.custom.fkn

# Numbers refer to suggestion list
1, 2, 4

# Only custom domains  
example.com, *.example.com, api.example.com
```

## Certificate Status

The tool provides clear status indicators for both service certificates and CA:

**Service Certificates:**
- ✅ **VALID**: Certificate is currently valid
- ⚠️ **EXPIRES SOON**: Certificate expires within 30 days
- ❌ **EXPIRED**: Certificate has expired

**CA Certificate:**
- ✅ **VALID**: CA certificate is currently valid (with days remaining)
- ⚠️ **EXPIRES SOON**: CA certificate expires within 30 days
- ❌ **EXPIRED**: CA certificate has expired

## Security Features

- Password-protected CA private keys
- Separate service configurations
- Certificate revocation support
- Strong default key sizes (2048-bit minimum)
- Automatic SAN extension generation

## ⚠️ Security Notice - Home Use Only

**This tool is designed for home and internal network use only.** It is NOT intended for production environments or public-facing services.

### 🔒 Critical Security Requirements

**Protect Your SSL Directory:**
- The SSL manager directory contains sensitive cryptographic material
- **CA private keys** can issue certificates for any domain
- **Service certificates** provide access to your internal services
- **Backup files** contain encrypted copies of all certificates

### 🛡️ Recommended Security Measures

**File System Security:**
```bash
# Set restrictive permissions on the SSL directory
chmod 700 /path/to/ssl-certificate-manager
chmod 600 /path/to/ssl-certificate-manager/root-ca.key
chmod 600 /path/to/ssl-certificate-manager/config.json
```

**Access Control:**
- Keep this directory on an encrypted disk/partition
- Limit access to authorized users only
- Consider using a dedicated user account for SSL operations
- Regular backup to encrypted external storage

**Network Security:**
- Use only on trusted internal networks
- Never expose CA operations to public networks
- Keep CA private keys offline when possible
- Use strong, unique passwords for CA and backups

### 🏠 Home Network Best Practices

**Internal Use Only:**
- Perfect for home labs, development environments
- Ideal for internal services (NAS, routers, IoT devices)
- Great for learning SSL/TLS concepts safely

**NOT for Production:**
- Do not use for public websites
- Do not use for commercial services  
- Do not use for critical infrastructure
- Consider commercial CA for production needs

### 💾 Backup Security

**Encrypted Backups:**
- All backups are encrypted with strong passwords
- Store backup files securely (encrypted storage)
- Test restore procedures regularly
- Keep backups offline when possible

**Password Management:**
- Use strong, unique passwords for CA operations
- Consider using a password manager
- Document recovery procedures securely
- Never store passwords in plain text

## Examples

### Create a certificate for a web service
```bash
python ssl.py --new webserver
# Follow prompts to select domains like webserver.lan, *.webserver.lan
```

### Check all certificate statuses
```bash
python ssl.py -l
```

### Renew an expiring certificate
```bash
python ssl.py --renew webserver
```

### Check CA certificate status and renew if needed
```bash
python ssl.py --ca-info   # Check CA expiration
python ssl.py --ca-renew  # Renew CA (archives old one)
```

### Revoke a compromised certificate
```bash
python ssl.py --revoke webserver
python ssl.py --crl  # View revoked certificates
```

## Certificate Installation

### Installing CA Certificate

To avoid SSL warnings, you need to install the CA certificate (`root-ca.crt`) as a trusted certificate authority.

#### Browser Installation

**Chrome/Chromium:**
1. Go to Settings → Privacy and security → Security → Manage certificates
2. Click "Authorities" tab
3. Click "Import" and select `root-ca.crt`
4. Check "Trust this certificate for identifying websites"

**Firefox:**
1. Go to Settings → Privacy & Security → Certificates → View Certificates
2. Click "Authorities" tab → "Import"
3. Select `root-ca.crt`
4. Check "Trust this CA to identify websites"

**Safari (macOS):**
1. Double-click `root-ca.crt` to open Keychain Access
2. Select "System" keychain
3. Right-click the certificate → Get Info
4. Expand "Trust" → Set "When using this certificate" to "Always Trust"

#### System Installation

**Linux (Ubuntu/Debian):**
```bash
# Copy CA certificate
sudo cp root-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# For applications using ca-certificates
sudo cp root-ca.crt /etc/ssl/certs/
sudo c_rehash /etc/ssl/certs/
```

**Linux (CentOS/RHEL):**
```bash
sudo cp root-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

**macOS:**
```bash
# Add to system keychain
sudo security add-trusted-cert -d -r trustRoot -k /System/Library/Keychains/SystemRootCertificates.keychain root-ca.crt
```

**Windows:**
1. Double-click `root-ca.crt`
2. Click "Install Certificate..."
3. Select "Local Machine" → Next
4. Select "Place all certificates in the following store" → Browse
5. Select "Trusted Root Certification Authorities" → OK
6. Complete the wizard

### Using Server Certificates

**Web Servers (Apache):**
```apache
SSLCertificateFile /path/to/cert.crt
SSLCertificateKeyFile /path/to/cert.key
SSLCertificateChainFile /path/to/root-ca.crt
```

**Web Servers (Nginx):**
```nginx
ssl_certificate /path/to/cert.pem;  # Combined certificate
ssl_certificate_key /path/to/cert.key;
```

**Docker Containers:**
```bash
# Mount certificates as volumes
docker run -v /path/to/certs:/certs myapp
```

## Backup and Restore

### Creating Encrypted Backups
```bash
# Create encrypted backup
python ssl.py --backup /path/to/backup.enc

# Backup specific service only
python ssl.py --backup /path/to/backup.enc --service proxy
```

### Restoring from Backups
```bash
# Restore from encrypted backup
python ssl.py --restore /path/to/backup.enc

# Handle conflicts during restore
# Options: skip, replace, or abort
```

The backup includes:
- All service certificates and keys
- Service configurations
- CA certificate and key
- Certificate revocation list

**Note:** Archived CA certificates in the `archive/` directory are not included in backups by default. Archive directories are kept locally for CA renewal history.

## Migration from Old Structure

If you have an existing manual certificate structure with `.ext` files, use the migration script:

```bash
# Migrate old structure to new format
python migrate.py
```

The migration script will:
- ✅ **Scan** for old structure: `<service>/<year>/cert.(crt|key|ext|csr)`
- ✅ **Extract domains** from `.ext` files (SAN entries)
- ✅ **Create config.json** for each service with extracted domains
- ✅ **Generate .pem files** (certificate + CA chain)
- ✅ **Secure private keys** with 600 permissions
- ✅ **Preserve all existing files** (no data loss)

**Before migration:**
```
proxy/
├── 2024/
│   ├── cert.crt
│   ├── cert.key
│   ├── cert.ext    # Contains: DNS:proxy.lan,DNS:*.proxy.lan
│   └── cert.csr
└── 2025/
    ├── cert.crt
    ├── cert.key
    ├── cert.ext
    └── cert.csr
```

**After migration:**
```
proxy/
├── config.json     # NEW: Contains extracted domains and settings
├── 2024/
│   ├── cert.crt
│   ├── cert.key
│   ├── cert.pem    # NEW: Combined certificate chain
│   ├── cert.ext    # PRESERVED
│   └── cert.csr    # PRESERVED
└── 2025/
    ├── cert.crt
    ├── cert.key
    ├── cert.pem    # NEW: Combined certificate chain
    ├── cert.ext    # PRESERVED
    └── cert.csr    # PRESERVED
```

## Requirements

- Python 3.6+
- OpenSSL
- Linux, macOS, or Windows with OpenSSL available
- `cryptography` library for backup encryption (install with `pip install cryptography`)

## Configuration Files

### Global Configuration (`config.json`)
Contains default values for CA creation and certificate generation, including:
- CA and certificate defaults
- **Local TLDs**: Array of TLDs used for domain suggestions (e.g., `["lan", "local", "fkn", "internal"]`)
- Organizational information

### Service Configuration (`<service>/config.json`)
Stores service-specific settings including:
- CA configuration used for this service
- Certificate defaults
- Domain list for easy regeneration

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch  
5. Create a Pull Request

## Support

For issues and questions, please use the GitHub issue tracker.