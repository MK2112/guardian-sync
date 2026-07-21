# guardian-sync

![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![GPG](https://img.shields.io/badge/GPG-Encryption-brightgreen.svg)
![Cloud Sync](https://img.shields.io/badge/Cloud%20Sync-Supported-blueviolet.svg)
![Build](https://github.com/MK2112/guardian-sync/actions/workflows/test.yml/badge.svg)

An encryption layer for zero-trust cloud storage.<br><br>
Files are automatically encrypted before they sync, and they get decrypted locally again when needed.

Beyond PGP (GPG), optional post-quantum encryption using ML-KEM-768 (NIST FIPS 203) is supported.<br>
This is enabled by default when dependencies are available, falling back to PGP-only otherwise.

## Features

- Automated encryption of files before they sync
- Automated decryption of files when they're updated
- Works with any cloud sync client
- Monitoring for local changes, event-based checking for remote changes

## Requirements

- Python 3.10.x or higher
- [GnuPG](https://gnupg.org/) installed on your system
- A cloud sync client installed and configured on your computer

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/MK2112/guardian-sync.git
   cd guardian-sync
   ```

2. Install the package (installs the `guardian-sync` CLI command and all dependencies):
   ```bash
   pip install .
   ```
   
   For development (editable mode):
   ```bash
   pip install -e .
   ```

3. Create a PGP key if you don't already have one:
   ```bash
   gpg --full-generate-key
   ```
   Follow the prompts to create your key. Remember the name you use for your key.

4. Create or update the configuration file (`config.json`):
   ```json
   {
     "local": {
       "monitored_path": "./secure_files",
       "decrypted_path": "./secure_files"
     },
     "sync_folder": {
       "path": "",
       "encrypted_folder": "encrypted_files"
     },
     "pgp": {
       "key_name": "your_key_name",
       "passphrase": "",
       "gnupghome": "~/.gnupg",
       "always_trust": false
     },
     "sync": {
       "check_interval": 60
     },
     "log_file": null
   }
   ```
   
   - Use `sync_folder.path` to specify the full path to your cloud sync folder
   - Set `pgp.key_name` to the name you used when creating your PGP key
   - Leave `pgp.passphrase` empty to be prompted each time *(functionality beyond this is under development)*
   - Set `pgp.always_trust` to `true` *only* if you understand the risks, by default it is `false`
   - Persisted logging is optional:
     - Set `log_file` to a path (e.g. `"guardian-sync.log"`) to enable file logging
     - Set `log_file` to `null` to disable file logging entirely (only console logs)
   - All files in the monitored directory are encrypted and synced
   - The tool automatically handles file overwrites and creates conflict files if both local and remote versions change independently

## Usage

### Quick Start

1. **Add files to encrypt:**  
   Place any files you want to keep secure into your chosen "monitored" directory (e.g. `secure_files/`).  
   
   *An example could be:*  
   ```bash
   echo "my-secret-password" > secure_files/passwords.txt
   ```

2. **Start guardian-sync:**  
   Run the application to automatically encrypt new or changed files in your monitored directory:

   ```bash
   guardian-sync
   ```
   You can specify a custom config file if needed:
   ```bash
   guardian-sync --config /path/to/your/config.json
   ```

### Auto-Start

To have guardian-sync start automatically, prompt for your GPG passphrase, and have guardian-sync run in the background:
```bash
guardian-sync --auto
```

On next login, a password prompt will re-appear. However, if you specified a custom config file, include it for automated authentication:
```bash
guardian-sync --auto --config /path/to/your/config.json
```

To remove auto-start again:
```bash
guardian-sync --auto --remove
```

## Quick Uninstall

```bash
python uninstall.py
```

### Tests

```bash
pytest ./tests/
```

It is *recommended* to use a strong, unique passphrase for your key.
If you specify your passphrase in the config file, *which is not recommended*, ensure the file is properly secured.
Only you should be in posession of your passphrase and private key

## License

MIT.
