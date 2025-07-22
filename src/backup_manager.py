"""
Backup and restore management for SSL Certificate Manager.
Handles encrypted backups and conflict resolution during restore.
"""

import json
import tempfile
import shutil
import tarfile
import os
from pathlib import Path
from datetime import datetime
import getpass

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class BackupManager:
    """Manages encrypted backups and restore operations."""
    
    def __init__(self, ca_cert_path="root-ca.crt", ca_key_path="root-ca.key", config_file="config.json"):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.config_file = config_file
    
    def generate_key_from_password(self, password):
        """Generate encryption key from password using PBKDF2."""
        if not CRYPTO_AVAILABLE:
            print("❌ Cryptography library not available! Install with: pip install cryptography")
            return None
        
        # Use a fixed salt for consistency (in production, this should be random and stored)
        salt = b'ssl_manager_backup_salt_2025'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def create_backup(self, backup_path, service_name=None, service_manager=None):
        """Create an encrypted backup of certificates and configurations."""
        if not CRYPTO_AVAILABLE:
            print("❌ Cryptography library not available!")
            print("💡 Install with: pip install cryptography")
            return False

        print("🔐 Creating encrypted backup...")
        
        # Get backup password
        password = getpass.getpass("🔑 Backup password: ")
        if not password:
            print("❌ Backup password is required!")
            return False
        
        confirm_password = getpass.getpass("🔑 Confirm password: ")
        if password != confirm_password:
            print("❌ Passwords don't match!")
            return False
        
        backup_path = Path(backup_path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Create temporary directory for backup content
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Copy files to backup
                backup_data = {}
                
                # Backup CA files
                if Path(self.ca_cert_path).exists():
                    shutil.copy2(self.ca_cert_path, temp_path)
                    backup_data['ca_cert'] = self.ca_cert_path
                
                if Path(self.ca_key_path).exists():
                    shutil.copy2(self.ca_key_path, temp_path)
                    backup_data['ca_key'] = self.ca_key_path
                
                # Backup global config
                if Path(self.config_file).exists():
                    shutil.copy2(self.config_file, temp_path)
                    backup_data['global_config'] = self.config_file
                
                # Backup CRL
                crl_file = Path("revoked_serials.txt")
                if crl_file.exists():
                    shutil.copy2(crl_file, temp_path)
                    backup_data['crl'] = str(crl_file)
                
                # Backup services
                if service_manager:
                    services = service_manager.find_existing_services()
                    if service_name:
                        if service_name in services:
                            services = [service_name]
                        else:
                            print(f"❌ Service '{service_name}' not found!")
                            return False
                    
                    backup_data['services'] = []
                    for service in services:
                        service_path = Path(service)
                        if service_path.exists():
                            service_backup = temp_path / service
                            shutil.copytree(service_path, service_backup)
                            backup_data['services'].append(service)
                
                # Save backup metadata
                with open(temp_path / "backup_metadata.json", 'w') as f:
                    json.dump({
                        'created': datetime.now().isoformat(),
                        'version': '1.0',
                        'data': backup_data
                    }, f, indent=2)
                
                # Create tar archive
                tar_path = temp_path.parent / "backup.tar"
                with tarfile.open(tar_path, 'w') as tar:
                    for item in temp_path.iterdir():
                        tar.add(item, arcname=item.name)
                
                # Encrypt the archive
                key = self.generate_key_from_password(password)
                if not key:
                    return False
                
                fernet = Fernet(key)
                
                with open(tar_path, 'rb') as f:
                    data = f.read()
                
                encrypted_data = fernet.encrypt(data)
                
                with open(backup_path, 'wb') as f:
                    f.write(encrypted_data)
                
                service_text = f" (service: {service_name})" if service_name else ""
                print(f"✅ Encrypted backup created{service_text}: {backup_path}")
                print(f"📊 Backup size: {backup_path.stat().st_size} bytes")
                return True
                
        except Exception as e:
            print(f"❌ Error creating backup: {e}")
            return False

    def restore_backup(self, backup_path, service_name=None):
        """Restore from an encrypted backup with conflict handling."""
        if not CRYPTO_AVAILABLE:
            print("❌ Cryptography library not available!")
            print("💡 Install with: pip install cryptography")
            return False

        backup_path = Path(backup_path)
        if not backup_path.exists():
            print(f"❌ Backup file not found: {backup_path}")
            return False

        print(f"🔄 Restoring from encrypted backup: {backup_path}")
        
        # Get backup password
        password = getpass.getpass("🔑 Backup password: ")
        if not password:
            print("❌ Backup password is required!")
            return False
        
        try:
            # Decrypt the backup
            key = self.generate_key_from_password(password)
            if not key:
                return False
            
            fernet = Fernet(key)
            
            with open(backup_path, 'rb') as f:
                encrypted_data = f.read()
            
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except Exception:
                print("❌ Failed to decrypt backup! Wrong password?")
                return False
            
            # Extract to temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                tar_path = temp_path / "backup.tar"
                
                with open(tar_path, 'wb') as f:
                    f.write(decrypted_data)
                
                # Extract tar archive
                extract_path = temp_path / "extracted"
                extract_path.mkdir()
                
                with tarfile.open(tar_path, 'r') as tar:
                    tar.extractall(extract_path)
                
                # Load metadata
                metadata_file = extract_path / "backup_metadata.json"
                if not metadata_file.exists():
                    print("❌ Invalid backup file: missing metadata")
                    return False
                
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                print(f"📋 Backup created: {metadata.get('created', 'Unknown')}")
                print(f"📦 Backup version: {metadata.get('version', 'Unknown')}")
                
                # Handle conflicts and restore files
                conflicts = []
                
                # Check for conflicts
                backup_data = metadata.get('data', {})
                
                # Check CA files
                if 'ca_cert' in backup_data and Path(self.ca_cert_path).exists():
                    conflicts.append(('CA Certificate', self.ca_cert_path))
                if 'ca_key' in backup_data and Path(self.ca_key_path).exists():
                    conflicts.append(('CA Key', self.ca_key_path))
                
                # Check global config
                if 'global_config' in backup_data and Path(self.config_file).exists():
                    conflicts.append(('Global Config', self.config_file))
                
                # Check services
                services_to_restore = backup_data.get('services', [])
                if service_name:
                    if service_name in services_to_restore:
                        services_to_restore = [service_name]
                    else:
                        print(f"❌ Service '{service_name}' not found in backup!")
                        return False
                
                for service in services_to_restore:
                    if Path(service).exists():
                        conflicts.append(('Service', service))
                
                # Handle conflicts
                if conflicts:
                    print(f"\n⚠️  Found {len(conflicts)} conflicts:")
                    for i, (item_type, path) in enumerate(conflicts, 1):
                        print(f"   {i}. {item_type}: {path}")
                    
                    print("\nConflict resolution options:")
                    print("   [s] Skip conflicting files")  
                    print("   [r] Replace all conflicting files")
                    print("   [a] Abort restore")
                    
                    choice = input("\n❓ Choose option [s/r/a]: ").strip().lower()
                    
                    if choice in ['a', 'abort']:
                        print("👋 Restore aborted.")
                        return False
                    elif choice not in ['s', 'skip', 'r', 'replace']:
                        print("❌ Invalid option. Aborting restore.")
                        return False
                    
                    skip_conflicts = choice in ['s', 'skip']
                else:
                    skip_conflicts = False
                
                # Perform restore
                restored_count = 0
                
                # Restore CA files
                for ca_type, ca_file in [('ca_cert', self.ca_cert_path), ('ca_key', self.ca_key_path)]:
                    if ca_type in backup_data:
                        source = extract_path / Path(ca_file).name
                        if source.exists():
                            if not Path(ca_file).exists() or not skip_conflicts:
                                shutil.copy2(source, ca_file)
                                # Set secure permissions on CA private key
                                if ca_type == 'ca_key':
                                    os.chmod(ca_file, 0o600)
                                    print(f"✅ Restored: {ca_file} (with secure permissions)")
                                else:
                                    print(f"✅ Restored: {ca_file}")
                                restored_count += 1
                            else:
                                print(f"⏭️  Skipped: {ca_file}")
                
                # Restore global config
                if 'global_config' in backup_data:
                    source = extract_path / Path(self.config_file).name
                    if source.exists():
                        if not Path(self.config_file).exists() or not skip_conflicts:
                            shutil.copy2(source, self.config_file)
                            print(f"✅ Restored: {self.config_file}")
                            restored_count += 1
                        else:
                            print(f"⏭️  Skipped: {self.config_file}")
                
                # Restore CRL
                if 'crl' in backup_data:
                    source = extract_path / "revoked_serials.txt"
                    if source.exists():
                        shutil.copy2(source, "revoked_serials.txt")
                        print(f"✅ Restored: revoked_serials.txt")
                        restored_count += 1
                
                # Restore services
                for service in services_to_restore:
                    source = extract_path / service
                    if source.exists():
                        if not Path(service).exists() or not skip_conflicts:
                            if Path(service).exists():
                                shutil.rmtree(service)
                            shutil.copytree(source, service)
                            
                            # Set secure permissions on all private key files in service
                            service_path = Path(service)
                            for key_file in service_path.rglob("*.key"):
                                os.chmod(key_file, 0o600)
                            
                            print(f"✅ Restored service: {service} (with secure key permissions)")
                            restored_count += 1
                        else:
                            print(f"⏭️  Skipped service: {service}")
                
                service_text = f" (service: {service_name})" if service_name else ""
                print(f"\n🎉 Restore completed{service_text}!")
                print(f"📊 Files restored: {restored_count}")
                return True
                
        except Exception as e:
            print(f"❌ Error restoring backup: {e}")
            return False