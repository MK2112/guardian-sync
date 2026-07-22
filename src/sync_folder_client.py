import os
import logging


class SyncFolderClient:
    def __init__(self, config):
        """Initialize sync folder client with configuration."""
        self.config = config
        # Get sync folder path from config or try to detect it
        self.sync_folder_path = os.path.expanduser(
            config.get("sync_folder", {}).get("path") or ""
        )
        if not self.sync_folder_path:
            self.sync_folder_path = self._detect_sync_folder_path()
        if not self.sync_folder_path or not os.path.exists(self.sync_folder_path):
            raise ValueError(
                "Sync folder not found. Please specify the full path in config.json using the 'sync_folder.path' setting."
            )
        self.encrypted_path = os.path.join(
            self.sync_folder_path,
            os.path.expanduser(
                config.get("sync_folder", {}).get("encrypted_folder", "encrypted_files")
            ),
        )
        # Create encrypted folder if it doesn't exist
        os.makedirs(self.encrypted_path, exist_ok=True)

    def _detect_sync_folder_path(self):
        """Try to detect a likely sync folder path (fallback for user convenience)."""
        possible_paths = [
            os.path.expanduser("~/SyncFolder"),
            os.path.expanduser("~/Dropbox"),
            os.path.expanduser("~/Google Drive"),
            os.path.expanduser("~/OneDrive"),
            os.path.expanduser("~/OneDrive - Personal"),
            os.path.expanduser("~/OneDrive - Business"),
            os.path.join(os.environ.get("USERPROFILE", ""), "OneDrive"),
            os.path.expanduser("~/Library/CloudStorage/OneDrive-Personal"),
            "/storage/emulated/0/OneDrive",
            "/sdcard/OneDrive",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                logging.info(f"Detected sync folder at: {path}")
                return path
        return None

    def list_files(self, folder_path=None):
        """List files in a sync folder."""
        folder = folder_path or self.encrypted_path
        files = []
        for root, _, filenames in os.walk(folder):
            for name in filenames:
                files.append(
                    {
                        "name": name,
                        "id": os.path.join(root, name),
                        "lastModifiedDateTime": os.path.getmtime(
                            os.path.join(root, name)
                        ),
                    }
                )
        return files

    def download_file(self, file_id, dest_path):
        """Download a file from the sync folder."""

        # If file_id is not an absolute path, search in encrypted_path and sync_folder_path
        def _is_within(base, target):
            # resolve real paths and ensure target is within base
            base_r = os.path.realpath(base)
            target_r = os.path.realpath(target)
            return target_r == base_r or target_r.startswith(base_r + os.sep)

        src = None
        if not os.path.isabs(file_id):
            candidate_bases = [self.encrypted_path, self.sync_folder_path]
            for base in candidate_bases:
                candidate = os.path.join(base, file_id)
                # prevent path traversal: resolve and ensure candidate remains inside base
                if os.path.exists(candidate) and _is_within(base, candidate):
                    src = os.path.realpath(candidate)
                    break
            if src is None:
                raise FileNotFoundError(f"File '{file_id}' not found in sync folder.")
        else:
            # absolute path provided: allow only if it resides within the sync folder
            if os.path.exists(file_id) and (
                _is_within(self.sync_folder_path, file_id)
                or _is_within(self.encrypted_path, file_id)
            ):
                src = os.path.realpath(file_id)
            else:
                raise FileNotFoundError(f"File '{file_id}' not found in sync folder.")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(src, "rb") as fsrc, open(dest_path, "wb") as fdst:
            fdst.write(fsrc.read())
        return dest_path

    def upload_file(self, src_path, dest_path=None):
        """Upload a file to the sync folder."""
        if dest_path is None:
            dest_path = os.path.join(self.encrypted_path, os.path.basename(src_path))
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        with open(src_path, "rb") as fsrc, open(dest_path, "wb") as fdst:
            fdst.write(fsrc.read())
        return {"id": dest_path, "name": os.path.basename(dest_path)}

    def ensure_folder_exists(self, folder_path):
        """Ensure a folder exists in the sync folder."""
        if os.path.isabs(folder_path):
            full_path = folder_path
        else:
            full_path = os.path.join(self.sync_folder_path, folder_path)
        os.makedirs(full_path, exist_ok=True)
        return {"id": folder_path, "name": os.path.basename(folder_path)}
