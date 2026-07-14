# Service templates

`keybroker.service` runs Keybroker as the unprivileged `deploy` account on Linux. Change the account before installation when the host uses a different service user.

`com.keybroker.service.plist` is a macOS launchd template. Replace `__KEYBROKER_BIN__` with the absolute path to the compiled CLI and `__KEYBROKER_LOG_DIR__` with an existing private log directory before loading it.

Both services use a local Unix socket. Neither opens a TCP listener.
