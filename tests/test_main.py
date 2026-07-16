import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
import pytest
from unittest import mock
from pathlib import Path


# Patch sys.argv for CLI tests
@mock.patch("main.setup_logging")
@mock.patch("main.check_android_permissions")
@mock.patch("main.load_config")
@mock.patch("main.HybridPGPHandler")
@mock.patch("main.SyncFolderClient")
@mock.patch("main.SyncManager")
@mock.patch("main.FileMonitor")
def test_main_entry(
    MockFileMonitor,
    MockSyncManager,
    MockODC,
    MockHybridPGP,
    MockLoadConfig,
    MockCheckAndroid,
    MockSetupLogging,
    tmp_path,
):
    config = {
        "local": {"monitored_path": str(tmp_path), "decrypted_path": str(tmp_path)},
        "sync_folder": {"path": str(tmp_path), "encrypted_folder": "encrypted_files"},
        "pgp": {"key_name": "dummy", "passphrase": "", "gnupghome": str(tmp_path)},
        "sync": {"check_interval": 1},
    }
    MockLoadConfig.return_value = config
    sys_argv = sys.argv
    sys.argv = ["guardian-sync", "--config", "dummy.json"]
    with mock.patch("signal.pause", side_effect=SystemExit):
        import main

        try:
            main.main()
        except SystemExit:
            pass
    sys.argv = sys_argv
    assert MockFileMonitor.called
    assert MockSyncManager.called
    assert MockODC.called
    assert MockHybridPGP.called


def test_get_service_path():
    import main

    expected = Path.home() / ".config" / "systemd" / "user" / "guardian-sync.service"
    assert main.get_service_path() == expected


@mock.patch("main.subprocess.run")
@mock.patch("main.input", return_value="")
@mock.patch("builtins.print")
def test_setup_auto_start_creates_service_file(
    mock_print, mock_input, mock_subproc_run, tmp_path
):
    import main

    config_path = tmp_path / "my-config.json"
    config_path.write_text("{}")

    with mock.patch.object(Path, "home", return_value=tmp_path):
        main.setup_auto_start(str(config_path))

    service_file = tmp_path / ".config" / "systemd" / "user" / "guardian-sync.service"
    assert service_file.exists()
    content = service_file.read_text()
    assert "guardian-sync" in content
    assert os.path.abspath(str(config_path)) in content
    call_cmds = [args[0] for args, _ in mock_subproc_run.call_args_list]
    assert ["daemon-reload"] in [c[2:] for c in call_cmds]
    assert ["enable", "guardian-sync.service"] in [c[2:] for c in call_cmds]


@mock.patch("main.subprocess.run")
@mock.patch("main.input", return_value="y")
@mock.patch("builtins.print")
def test_setup_auto_start_starts_service_on_yes(
    mock_print, mock_input, mock_subproc_run, tmp_path
):
    import main

    config_path = tmp_path / "my-config.json"
    config_path.write_text("{}")

    with mock.patch.object(Path, "home", return_value=tmp_path):
        main.setup_auto_start(str(config_path))

    call_cmds = [args[0] for args, _ in mock_subproc_run.call_args_list]
    assert any("start" in cmd for cmd in call_cmds)


@mock.patch("main.subprocess.run")
@mock.patch("builtins.print")
def test_setup_auto_start_systemctl_not_found(mock_print, mock_subproc_run, tmp_path):
    import main

    mock_subproc_run.side_effect = FileNotFoundError("no systemctl")
    config_path = tmp_path / "my-config.json"
    config_path.write_text("{}")

    with mock.patch.object(Path, "home", return_value=tmp_path):
        with pytest.raises(SystemExit):
            main.setup_auto_start(str(config_path))


@mock.patch("main.subprocess.run")
@mock.patch("builtins.print")
def test_remove_auto_stops_disables_removes_service(
    mock_print, mock_subproc_run, tmp_path
):
    import main

    service_file = tmp_path / ".config" / "systemd" / "user" / "guardian-sync.service"
    service_file.parent.mkdir(parents=True, exist_ok=True)
    service_file.write_text("[Unit]\n")

    with mock.patch.object(Path, "home", return_value=tmp_path):
        main.remove_auto_start()

    assert not service_file.exists()
    call_cmds = [args[0] for args, _ in mock_subproc_run.call_args_list]
    assert any("stop" in cmd for cmd in call_cmds)
    assert any("disable" in cmd for cmd in call_cmds)
    assert any("daemon-reload" in cmd for cmd in call_cmds)


@mock.patch("main.subprocess.run")
@mock.patch("builtins.print")
def test_remove_auto_no_service_file(mock_print, mock_subproc_run, tmp_path):
    import main

    with mock.patch.object(Path, "home", return_value=tmp_path):
        main.remove_auto_start()
    mock_print.assert_any_call("Auto-start removed.")


@mock.patch("main.setup_auto_start")
def test_main_auto_flag_calls_setup(mock_setup, tmp_path):
    import main

    sys_argv = sys.argv
    sys.argv = ["guardian-sync", "--auto"]
    try:
        main.main()
    except SystemExit:
        pass
    sys.argv = sys_argv
    assert mock_setup.called


@mock.patch("main.remove_auto_start")
def test_main_auto_remove_flag_calls_remove(mock_remove, tmp_path):
    import main

    sys_argv = sys.argv
    sys.argv = ["guardian-sync", "--auto", "--remove"]
    try:
        main.main()
    except SystemExit:
        pass
    sys.argv = sys_argv
    assert mock_remove.called


@mock.patch("main.setup_auto_start")
def test_main_auto_passes_config(mock_setup):
    import main

    sys_argv = sys.argv
    sys.argv = ["guardian-sync", "--auto", "--config", "/custom/config.json"]
    try:
        main.main()
    except SystemExit:
        pass
    sys.argv = sys_argv
    mock_setup.assert_called_once_with("/custom/config.json")
