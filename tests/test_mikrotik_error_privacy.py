"""Device/transport failures must not disclose credential-bearing input."""

import logging
import traceback
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from provisioner.handlers.mikrotik import MikrotikHandler


PRIVATE = "synthetic-sensitive-value-for-error-tests"
COMMAND = '/user set example password="%s"' % PRIVATE


def handler_with_ssh():
    handler = MikrotikHandler("192.0.2.1", {"username": "example", "password": PRIVATE})
    handler._ensure_ssh = AsyncMock()
    handler._ssh = MagicMock()
    handler._ssh.run = AsyncMock()
    return handler


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", ["stdout", "stderr", "neither"])
async def test_command_failure_withholds_reply_and_command(stream):
    handler = handler_with_ssh()
    result = SimpleNamespace(exit_status=1, stdout="", stderr="")
    if stream != "neither":
        setattr(result, stream, COMMAND)
    handler._ssh.run.return_value = result

    with pytest.raises(RuntimeError) as failure:
        await handler._run_command(COMMAND)

    assert "command failed" in str(failure.value)
    assert PRIVATE not in str(failure.value)
    assert COMMAND not in str(failure.value)


@pytest.mark.asyncio
async def test_allowed_command_failure_does_not_return_error_body():
    handler = handler_with_ssh()
    handler._ssh.run.return_value = SimpleNamespace(exit_status=1, stdout=PRIVATE, stderr=COMMAND)
    assert await handler._run_command(COMMAND, allow_failure=True) == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("allow_failure", [False, True])
async def test_success_keeps_readback_output(allow_failure):
    handler = handler_with_ssh()
    handler._ssh.run.return_value = SimpleNamespace(exit_status=0, stdout=" verified\n", stderr="")
    assert await handler._run_command("/system identity print", allow_failure) == "verified"


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["connect", "run"])
async def test_transport_error_is_not_chained_into_public_traceback(stage):
    handler = handler_with_ssh()
    target = handler._ensure_ssh if stage == "connect" else handler._ssh.run
    target.side_effect = RuntimeError(COMMAND)

    with pytest.raises(RuntimeError) as failure:
        await handler._run_command(COMMAND)

    error = failure.value
    rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    assert "could not complete" in str(error)
    assert PRIVATE not in rendered
    assert error.__suppress_context__


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("exit_status", [0, 1])
async def test_import_failure_does_not_log_echoed_config(tmp_path, caplog, stream, exit_status):
    handler = handler_with_ssh()
    source = tmp_path / "config.rsc"
    source.write_text(COMMAND)
    sftp = handler._ssh.start_sftp_client.return_value.__aenter__.return_value
    sftp.put = AsyncMock()
    result = SimpleNamespace(exit_status=exit_status, stdout="", stderr="")
    setattr(result, stream, "failure: " + COMMAND)
    handler._ssh.run.return_value = result

    with caplog.at_level(logging.DEBUG):
        assert not await handler.apply_config_file(str(source))

    assert "Config import failed" in caplog.text
    assert PRIVATE not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["upload", "import"])
async def test_import_transport_failure_does_not_log_exception(tmp_path, caplog, stage):
    handler = handler_with_ssh()
    source = tmp_path / "config.rsc"
    source.write_text(COMMAND)
    sftp = handler._ssh.start_sftp_client.return_value.__aenter__.return_value
    sftp.put = AsyncMock()
    target = sftp.put if stage == "upload" else handler._ssh.run
    target.side_effect = RuntimeError(COMMAND)

    with caplog.at_level(logging.DEBUG):
        assert not await handler.apply_config_file(str(source))

    assert "Failed to apply MikroTik config file" in caplog.text
    assert PRIVATE not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("authentication", [False, True])
async def test_connection_errors_do_not_reach_kiosk_or_logs(caplog, authentication):
    handler = handler_with_ssh()
    message = ("permission denied " if authentication else "SSH error ") + PRIVATE
    handler._open_ssh_connection = AsyncMock(side_effect=RuntimeError(message))

    with caplog.at_level(logging.DEBUG):
        assert not await handler.connect()

    assert PRIVATE not in caplog.text
    assert PRIVATE not in handler.login_error
    assert ("Invalid credentials" in handler.login_error) == authentication


@pytest.mark.asyncio
async def test_failed_login_probe_does_not_publish_server_reply(caplog):
    handler = handler_with_ssh()
    connection = MagicMock()
    connection.run = AsyncMock(return_value=SimpleNamespace(exit_status=1, stderr=PRIVATE))
    connection.wait_closed = AsyncMock()
    handler._open_ssh_connection = AsyncMock(return_value=connection)

    with caplog.at_level(logging.DEBUG):
        assert not await handler.connect()

    assert handler.login_error == "SSH login probe failed"
    assert PRIVATE not in caplog.text
