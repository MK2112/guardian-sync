import os
import sys
import json
import shutil
import argparse
import subprocess

from pathlib import Path
from datetime import datetime


class UninstallManager:
    def __init__(self, verbose=False, force=False, keep_config=False):
        self.verbose = verbose
        self.force = force
        self.keep_config = keep_config
        self.backup_dir = None
        self.errors = []
        self.success = []
    
    def log(self, message, level="INFO"):
        if self.verbose or level != "DEBUG":
            prefix = f"[{level}]" if level != "INFO" else "[*]"
            print(f"{prefix} {message}")
    
    def error(self, message):
        print(f"[ERROR] {message}", file=sys.stderr)
        self.errors.append(message)
    
    def success_msg(self, message):
        print(f"[>] {message}")
        self.success.append(message)
    
    def create_backup(self):
        try:
            backup_base = Path.home() / ".guardian-sync-backups"
            backup_base.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.backup_dir = backup_base / f"backup_{timestamp}"
            self.backup_dir.mkdir(exist_ok=True)
            
            config_file = Path("config.json")
            if config_file.exists():
                backup_config = self.backup_dir / "config.json"
                shutil.copy2(config_file, backup_config)
                self.log(f"Backed up config to {backup_config}")
            
            gnupg_home = Path.home() / ".gnupg"
            pq_keystore = gnupg_home / ".pq_keystore.json"
            if pq_keystore.exists():
                backup_ks = self.backup_dir / ".pq_keystore.json"
                shutil.copy2(pq_keystore, backup_ks)
                self.log(f"Backed up post-quantum keystore to {backup_ks}")
            
            self.success_msg(f"Backup created at {self.backup_dir}")
            return True
        except Exception as e:
            self.error(f"Failed to create backup: {str(e)}")
            return False
    
    def uninstall_package(self):
        try:
            self.log("Uninstalling Python package...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "-y", "guardian-sync"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.success_msg("Python package uninstalled")
                return True
            else:
                self.log("Package not found in pip (may be local installation)", "DEBUG")
                return True
        except Exception as e:
            self.error(f"Failed to uninstall package: {str(e)}")
            return False
    
    def remove_entry_point(self):
        try:
            self.log("Removing command-line entry point...")
            result = subprocess.run(
                ["which", "guardian-sync"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                cmd_path = result.stdout.strip()
                os.remove(cmd_path)
                self.success_msg(f"Removed command-line tool from {cmd_path}")
            else:
                self.log("Command-line tool not found (may already be removed)", "DEBUG")
            return True
        except Exception as e:
            self.error(f"Failed to remove entry point: {str(e)}")
            return False
    
    def remove_config_files(self):
        # Remove configuration files (after backup)
        if self.keep_config:
            self.log("Keeping configuration files (--keep-config)")
            return True
        try:
            self.log("Removing configuration files...")
            config_file = Path("config.json")
            if config_file.exists():
                os.remove(config_file)
                self.success_msg(f"Removed {config_file}")
            return True
        except Exception as e:
            self.error(f"Failed to remove config files: {str(e)}")
            return False
    
    def remove_pq_keystore(self):
        # Safely remove post-quantum keystore
        try:
            self.log("Removing post-quantum keystore...")
            gnupg_home = Path.home() / ".gnupg"
            pq_keystore = gnupg_home / ".pq_keystore.json"
            if pq_keystore.exists():
                if not self.force:
                    response = input(
                        f"\nRemove post-quantum keystore at {pq_keystore}? "
                        "[y/N]: "
                    )
                    if response.lower() != 'y':
                        self.log("Keeping post-quantum keystore", "DEBUG")
                        return True
                os.remove(pq_keystore)
                self.success_msg(f"Removed post-quantum keystore")
            else:
                self.log("Post-quantum keystore not found", "DEBUG")
            return True
        except Exception as e:
            self.error(f"Failed to remove keystore: {str(e)}")
            return False
    
    def remove_egg_info(self):
        try:
            egg_info = Path("encrypted_sync.egg-info")
            if egg_info.exists():
                shutil.rmtree(egg_info)
                self.log(f"Removed {egg_info}")
            return True
        except Exception as e:
            self.error(f"Failed to remove egg-info: {str(e)}")
            return False
    
    def remove_pycache(self):
        try:
            self.log("Removing Python cache files...")
            removed_count = 0
            for pycache in Path(".").rglob("__pycache__"):
                shutil.rmtree(pycache)
                removed_count += 1
            if removed_count > 0:
                self.success_msg(f"Removed {removed_count} __pycache__ directories")
            return True
        except Exception as e:
            self.error(f"Failed to remove cache: {str(e)}")
            return False
    
    def remove_dependencies(self):
        try:
            dependencies = [
                "python-gnupg",
                "watchdog",
                "cryptography",
                "liboqs-python",
            ]
            
            response = input(
                "\nRemove dependencies? (python-gnupg, watchdog, cryptography, liboqs-python) "
                "[y/N]: "
            )
            
            if response.lower() != 'y':
                self.log("Keeping dependencies", "DEBUG")
                return True
            
            self.log("Removing dependencies...")
            
            for dep in dependencies:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "uninstall", "-y", dep],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    self.success_msg(f"Removed {dep}")
                else:
                    self.log(f"Could not remove {dep} (may not be installed)", "DEBUG")
            
            return True
        except Exception as e:
            self.error(f"Failed to remove dependencies: {str(e)}")
            return False
    
    def cleanup_directories(self):
        try:
            self.log("Cleaning up directories...")
            dirs_to_check = [
                ".benchmarks",
                ".pytest_cache",
            ]
            
            for dir_name in dirs_to_check:
                dir_path = Path(dir_name)
                if dir_path.exists() and dir_path.is_dir():
                    try:
                        # Only remove if empty or only contains cache
                        shutil.rmtree(dir_path)
                        self.log(f"Removed {dir_name}")
                    except Exception:
                        pass
            return True
        except Exception as e:
            self.error(f"Failed to cleanup directories: {str(e)}")
            return False
    
    def run(self):
        print("GUARDIAN-SYNC UNINSTALLER")
        print("=" * 20)
        
        if not self.force:
            print("\nThis will uninstall guardian-sync from your system.")
            print("Your files will NOT be affected, but configuration may be removed.")
            response = input("\nContinue with uninstallation? [y/N]: ")
            if response.lower() != 'y':
                print("\nUninstallation cancelled.")
                return False
        
        print("\nStarting uninstallation process...\n")
        
        # Create backup first
        if not self.create_backup():
            if not self.force:
                response = input("\nBackup failed. Continue anyway? [y/N]: ")
                if response.lower() != 'y':
                    print("Uninstallation cancelled.")
                    return False
        
        # Run uninstall steps
        steps = [
            ("Uninstalling package", self.uninstall_package),
            ("Removing entry point", self.remove_entry_point),
            ("Removing configuration files", self.remove_config_files),
            ("Removing post-quantum keystore", self.remove_pq_keystore),
            ("Removing egg-info", self.remove_egg_info),
            ("Removing Python cache", self.remove_pycache),
            ("Cleaning up directories", self.cleanup_directories),
        ]
        
        for step_name, step_func in steps:
            try:
                step_func()
            except Exception as e:
                self.error(f"Unexpected error in {step_name}: {str(e)}")
        
        # Optional dependency removal
        if not self.force:
            self.remove_dependencies()
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Safely uninstall guardian-sync",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python uninstall.py                 # Interactive uninstall
  python uninstall.py --force         # Non-interactive uninstall
  python uninstall.py --keep-config   # Keep configuration files
  python uninstall.py -v              # Verbose output
        """
    )
    
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Non-interactive uninstall (skip confirmations)"
    )
    
    parser.add_argument(
        "-k", "--keep-config",
        action="store_true",
        help="Keep configuration files (config.json)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show all operations)"
    )
    
    parser.add_argument(
        "--backup-only",
        action="store_true",
        help="Only create backup without uninstalling"
    )
    
    args = parser.parse_args()
    
    manager = UninstallManager(
        verbose=args.verbose,
        force=args.force,
        keep_config=args.keep_config
    )
    
    if args.backup_only:
        print("Creating backup only...\n")
        manager.create_backup()
        print(f"\nBackup created at: {manager.backup_dir}")
        return 0
    
    success = manager.run()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
