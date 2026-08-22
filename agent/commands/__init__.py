from .syn_flood import SynFloodCommand
from .isolate import IsolateCommand
# ... import các command khác

COMMAND_HANDLERS = {
    SynFloodCommand.name: SynFloodCommand(),
    IsolateCommand.name: IsolateCommand(),
}