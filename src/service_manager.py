"""
Service management for SSL Certificate Manager.
Handles service operations, validation, and listing.
"""

import re
import shutil
from pathlib import Path
from datetime import datetime


class ServiceManager:
    """Manages SSL service operations."""
    
    # Reserved directory names that cannot be used as service names
    RESERVED_NAMES = {
        'src', '__pycache__', '.git', '.vscode', '.idea', 
        'node_modules', 'venv', 'env', '.env', 'dist', 'build'
    }
    
    def __init__(self):
        pass
    
    def validate_service_name(self, name):
        """Validates the service name."""
        if not name:
            return False, "Service name cannot be empty!"
        
        if name.lower() in self.RESERVED_NAMES:
            return False, f"'{name}' is a reserved directory name and cannot be used as service name!"
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', name):
            return False, "Service name may only contain letters, numbers, underscores and hyphens!"
        
        if len(name) < 2:
            return False, "Service name must be at least 2 characters long!"
        
        return True, ""

    def find_existing_services(self):
        """Finds all existing service directories."""
        services = []
        current_dir = Path(".")
        for item in current_dir.iterdir():
            if item.is_dir() and not item.name.startswith('.') and item.name not in self.RESERVED_NAMES:
                # Check if it's a service directory (has subdirectories with years)
                year_dirs = [d for d in item.iterdir() if d.is_dir() and d.name.isdigit()]
                if year_dirs:
                    services.append(item.name)
        return sorted(services)

    def show_service_info(self, service_name, certificate_manager, config_manager):
        """Shows detailed information about a service."""
        service_path = Path(service_name)
        if not service_path.exists():
            print(f"❌ Service '{service_name}' not found!")
            return
        
        print(f"📋 Service Information: {service_name}")
        print("=" * 50)
        
        # Load config
        config = config_manager.load_service_config(service_path)
        if config:
            print("🔧 Configuration:")
            if config.get("domains"):
                print("   🌐 Domains:")
                for domain in config["domains"]:
                    print(f"      • {domain}")
            print()
        
        # List all certificates in all years
        year_dirs = [d for d in service_path.iterdir() if d.is_dir() and d.name.isdigit()]
        if not year_dirs:
            print("📄 No certificates found.")
            return
        
        for year_dir in sorted(year_dirs, key=lambda x: int(x.name), reverse=True):
            cert_path = year_dir / "cert.crt"
            if cert_path.exists():
                dates = certificate_manager.parse_certificate_dates(cert_path)
                if dates:
                    print(f"📅 Year {year_dir.name}:")
                    print(f"   📜 Certificate: {cert_path}")
                    print(f"   📅 Issued: {dates['issued'].strftime('%d.%m.%Y %H:%M')}")
                    print(f"   ⏰ Expires: {dates['expires'].strftime('%d.%m.%Y %H:%M')}")
                    
                    now = datetime.now()
                    if dates['expires'] < now:
                        print("   ❌ Status: EXPIRED")
                    elif (dates['expires'] - now).days <= 30:
                        print("   ⚠️  Status: EXPIRES SOON")
                    else:
                        print("   ✅ Status: VALID")
                    print()

    def delete_service(self, service_name):
        """Deletes a service and all associated files."""
        service_path = Path(service_name)
        if not service_path.exists():
            print(f"❌ Service '{service_name}' not found!")
            return False
        
        print(f"🗑️  Delete service '{service_name}' and all certificates...")
        
        # Security confirmation
        confirm = input(f"⚠️  Really delete '{service_name}'? [j/N]: ").strip().lower()
        if confirm not in ['j', 'ja', 'y', 'yes']:
            print("👋 Deletion cancelled.")
            return False
        
        try:
            shutil.rmtree(service_path)
            print(f"✅ Service '{service_name}' successfully deleted!")
            return True
        except Exception as e:
            print(f"❌ Error deleting: {e}")
            return False

    def scan_certificates(self, certificate_manager):
        """Scans all services for certificates and shows expiration dates."""
        services = self.find_existing_services()
        if not services:
            print("📄 No services with certificates found.")
            return

        print("📋 Certificate Overview")
        print("=" * 70)
        
        cert_info = []
        
        for service_name in services:
            service_path = Path(service_name)
            
            # Find all years for this service
            year_dirs = [d for d in service_path.iterdir() if d.is_dir() and d.name.isdigit()]
            if not year_dirs:
                continue
                
            # Use newest year (highest number)
            latest_year_dir = max(year_dirs, key=lambda x: int(x.name))
            cert_path = latest_year_dir / "cert.crt"
            
            if not cert_path.exists():
                continue
                
            # Read certificate data
            dates = certificate_manager.parse_certificate_dates(cert_path)
            if not dates:
                continue
            
            # Determine status
            now = datetime.now()
            if dates['expires'] < now:
                status = "❌ EXPIRED"
            elif (dates['expires'] - now).days <= 30:
                status = "⚠️  EXPIRES SOON"
            else:
                status = "✅ VALID"
            
            cert_info.append({
                'service': service_name,
                'status': status,
                'issued': dates['issued'],
                'expires': dates['expires'],
                'days_left': (dates['expires'] - now).days
            })
        
        # Sort by expiration date (most critical first)
        cert_info.sort(key=lambda x: x['expires'])
        
        # Output
        for info in cert_info:
            issued_str = info['issued'].strftime('%d.%m.%Y %H:%M')
            expires_str = info['expires'].strftime('%d.%m.%Y %H:%M')
            
            print(f"🏷️  {info['service']:<20} {info['status']}")
            print(f"   📅 Issued on: {issued_str}")
            print(f"   ⏰ Expires on: {expires_str}")
            
            if info['days_left'] >= 0:
                print(f"   📊 Valid for {info['days_left']} more day(s)")
            else:
                print(f"   📊 Expired {abs(info['days_left'])} day(s) ago")
            print()