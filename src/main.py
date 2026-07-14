import os
import sys
import json
import logging
import argparse
import signal
import subprocess

from pathlib import Path

try:
    from .pgp_handler import PGPHandler
    from .sync_folder_client import SyncFolderClient
    from .file_monitor import FileMonitor
    from .sync_manager import SyncManager
except ImportError:
    from pgp_handler import PGPHandler
    from sync_folder_client import SyncFolderClient
    from file_monitor import FileMonitor
    from sync_manager import SyncManager

AUTO_START_SERVICE_NAME = "guardian-sync.service"

SERVICE_TEMPLATE = """\
[Unit]
Description=guardian-sync - Encrypted Cloud Sync Middleware
Documentation=https://github.com/MK2112/guardian-sync
After=network.target

[Service]
Type=simple
ExecStartPre=/bin/sh -c 'PASS=$(systemd-ask-password --emoji=no "Enter GPG passphrase for guardian-sync:"); printf "%s" "$PASS" > %t/guardian-sync.pass'
ExecStart=/bin/sh -c 'PASS=$(cat %t/guardian-sync.pass); rm -f %t/guardian-sync.pass; export GUARDIAN_SYNC_PASSPHRASE="$PASS"; exec guardian-sync --config "{config_path}"'
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
"""


def load_config(config_path):
    with open(config_path, "r") as f:
        return json.load(f)


def setup_logging(log_file: str | None):
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


def check_android_permissions():
    try:
        if os.path.exists("/data/data/com.termux"):
            logging.info("Running on Android through Termux")
            if not os.access("/storage/emulated/0", os.R_OK | os.W_OK):
                logging.warning("Storage access not available.")
                print(
                    "Storage access not available. Please run 'termux-setup-storage' in Termux and restart the app."
                )
                sys.exit(1)
    except Exception as e:
        logging.warning(f"Error checking Android permissions: {str(e)}")


def get_service_path():
    return Path.home() / ".config" / "systemd" / "user" / AUTO_START_SERVICE_NAME


def setup_auto_start(config_path):
    service_path = get_service_path()
    systemd_user_dir = service_path.parent
    systemd_user_dir.mkdir(parents=True, exist_ok=True)

    abs_config_path = os.path.abspath(config_path)
    service_content = SERVICE_TEMPLATE.format(config_path=abs_config_path)

    with open(service_path, "w") as f:
        f.write(service_content)

    try:
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"], check=True, capture_output=True
        )
        subprocess.run(
            ["systemctl", "--user", "enable", AUTO_START_SERVICE_NAME],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to configure systemd service: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(
            "systemctl not found. systemd may not be available on this system.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Auto-start service installed: {service_path}")
    print(
        "On next login, guardian-sync will prompt for your GPG passphrase and run in the background."
    )
    response = input("Start service now? [Y/n]: ").strip().lower()
    if response in ("", "y", "yes"):
        try:
            subprocess.run(
                ["systemctl", "--user", "start", AUTO_START_SERVICE_NAME], check=True
            )
            print("Service started.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to start service: {e}", file=sys.stderr)


def remove_auto_start():
    service_path = get_service_path()

    try:
        subprocess.run(
            ["systemctl", "--user", "stop", AUTO_START_SERVICE_NAME],
            capture_output=True,
        )
        subprocess.run(
            ["systemctl", "--user", "disable", AUTO_START_SERVICE_NAME],
            capture_output=True,
        )
    except FileNotFoundError:
        pass

    if service_path.exists():
        service_path.unlink()

    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    except FileNotFoundError:
        pass

    print("Auto-start removed.")


def main():
    parser = argparse.ArgumentParser(
        description="guardian-sync: PGP Encryption Middleware for any cloud sync folder"
    )
    parser.add_argument(
        "--config", default="config.json", help="Path to configuration file"
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Install auto-start on boot (systemd user service)",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Used with --auto to remove auto-start instead of installing",
    )
    args = parser.parse_args()

    if args.auto:
        if args.remove:
            remove_auto_start()
        else:
            setup_auto_start(args.config)
        return

    try:
        check_android_permissions()

        config = load_config(args.config)
        log_file = config.get("log_file", None)
        setup_logging(log_file)

        pgp_handler = PGPHandler(config)
        sync_folder_client = SyncFolderClient(config)

        sync_manager = SyncManager(config, sync_folder_client, pgp_handler)

        file_monitor = FileMonitor(
            config["local"]["monitored_path"], sync_manager.handle_local_change
        )

        def signal_handler(sig, frame):
            logging.info("Shutting down...")
            sync_manager.stop()
            file_monitor.stop()
            pgp_handler.clear_passphrase()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        sync_manager.start()
        file_monitor.start()

        logging.info("guardian-sync: PGP Encryption Middleware started")

        while True:
            signal.pause()

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
