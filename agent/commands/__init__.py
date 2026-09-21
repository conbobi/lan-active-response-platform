from .syn_flood import SynFloodCommand
from .isolate import IsolateCommand
from .unisolate import UnisolateCommand
from .kill_process import KillProcessCommand
from .kill_process_tree import KillProcessTreeCommand
from .self_update import SelfUpdateCommand
from .quarantine import QuarantineCommand, ReleaseQuarantineCommand
from .yara_scan import YaraScanCommand

COMMAND_HANDLERS = {
    SynFloodCommand.name: SynFloodCommand(),
    IsolateCommand.name: IsolateCommand(),
    UnisolateCommand.name: UnisolateCommand(),
    KillProcessCommand.name: KillProcessCommand(),
    KillProcessTreeCommand.name: KillProcessTreeCommand(),
    SelfUpdateCommand.name: SelfUpdateCommand(),
    QuarantineCommand.name: QuarantineCommand(),
    ReleaseQuarantineCommand.name: ReleaseQuarantineCommand(),
    YaraScanCommand.name: YaraScanCommand(),
}