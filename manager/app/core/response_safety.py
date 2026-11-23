"""Common command names and confirmation requirements for destructive responses."""

KILL_ACTIONS = {"kill_process", "kill_process_tree"}
VERIFIED_KILL_COMMANDS = {f"{action}_verified" for action in KILL_ACTIONS}
CONFIRMATION_REQUIRED = KILL_ACTIONS | {
    "kill", "isolate", "auto_isolate", "quarantine", "block_ip", "remove_registry", "suspend_process",
}
PROTECTED_COMMANDS = CONFIRMATION_REQUIRED | VERIFIED_KILL_COMMANDS
