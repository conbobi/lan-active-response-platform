"""
Backward compatibility alias for app.services.core.command_dispatcher.
"""
from app.services.core.command_dispatcher import CommandDispatcher, command_dispatcher

__all__ = ["CommandDispatcher", "command_dispatcher"]
