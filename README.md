# port-checker

**Which port can I use, and who is on that one?**

`ports` looks at your own laptop and gives every port one plain verdict, such as "free", "in use by node (pid 4312)"
or "reserved for MySQL". For every port in use it shows the program and, when there is one, the pm2 app behind it.
It also keeps a small registry of the ports you've claimed, finds the next safe port for a new project, and warns
you when what's running stops matching what you wrote down. A local dashboard links straight to every web app on
your machine.

- Python 3.9+ standard library only: no packages to install, nothing sent anywhere.
- Windows, Linux and macOS.
- pm2 is optional: if you use it, `ports` knows which pm2 app owns each port.

```
$ ports check 3000
3000 is in use by node.exe pid 18812 (pm2 my-api) on 127.0.0.1; registered to My API.

$ ports next
8102

$ ports open 8101
opening http://127.0.0.1:8101/  Admin · Shop
```

## Install

```bash
pipx install git+https://github.com/ayushlal-oss/port-checker
# or
pip install git+https://github.com/ayushlal-oss/port-checker
```

You can also download the repo, then run `pip install .` inside it, or run it in place with `python ports.py <command>`.

## First run

```bash
ports init           # creates ~/.port-checker/config.json and ~/.port-checker/Ports.md (your registry)
ports ls             # everything listening right now, with its owner
ports adopt --write  # record everything that's running now, so the audit starts clean
ports serve          # dashboard on http://127.0.0.1:8801
```

## Commands

| Command | What it does |
|---|---|
| `ports ls [--json] [--all] [--urls]` | Lists every listening port and every port in your registry with a verdict, the bind address (loopback / all / lan), the PID and the owner. `--all` adds the OS dynamic range. `--urls` finds which ports serve a web page. |
| `ports check <port>` | Gives one sentence about one port. Exit code 0 only when the port is free, so you can use it in scripts. |
| `ports next [pool]` | Returns the next safe port in a pool (default `app`, 8100-8999). It always picks a port above the highest one you've registered, so a port is never reused. |
| `ports open <port>` | Opens the app on that port in your browser, if it serves a web page. |
| `ports audit` | Shows where your registry, pm2 and the machine disagree. Exit code 1 when it finds something. |
| `ports claim <port> --pool app --name <name> --project <project> [--cmd "<start command>"]` | Adds a row to the registry. |
| `ports retire <port>` | Marks a row as retired. The row stays, so the port is never handed out again. |
| `ports adopt` | Registers everything that's listening now and has no row yet. |
| `ports pools` | Lists your pools and the next free port in each. |
| `ports serve [--port 8801]` | Starts a read-only dashboard on 127.0.0.1. |

`claim`, `retire` and `adopt` only print the change unless you add `--write`. With `--write` they:
- back up the registry first (to `~/.port-checker/backups/`);
- write the new version in one step, so a failed write never leaves a half-written file;
- refuse (exit 3) if the file changed while they were working, for example during a cloud sync.

### Verdicts

| Verdict | Meaning |
|---|---|
| free | Nothing listens there, and the port isn't registered, reserved or blocked. You can use it. |
| in use | A process listens there. |
| down | It's registered, but nothing listens: the service has stopped. The port is still taken. |
| reserved | Listed under *Reserved*, for things like databases that aren't running right now. |
| transient | A port that's only open while some task runs. |
| retired | It was used before and is never handed out again. |
| excluded | Windows reserves this range (Hyper-V, WSL, Docker), so binding to it fails even though it looks free. |

### What the audit finds

- **registered-down:** a port registered as online, but nothing listens on it.
- **unregistered-listener:** something listens, but it has no row and isn't on the ignore list.
- **pm2-unregistered, pm2-not-online, pm2-missing:** pm2 and the registry disagree.
- **port-mismatch:** an app is listening on a port other than the one registered for it.
- **unsaved:** pm2 is running apps that `pm2 save` hasn't stored, so they won't come back after a reboot.
- **exposed:** a service listens beyond 127.0.0.1. This check is opt-in, through `loopback_only_sections`.
- **next-free-stale:** a "(next free)" row in your registry is out of date.

## The dashboard

`ports serve` opens a page at http://127.0.0.1:8801. It shows:
- the audit result;
- how many ports are listening;
- the next free port in each pool;
- a box to check any port;
- the full table, with filters (all, in use, web apps, not listening, drift).

Every port that serves a web page is a link to that app, with its page title underneath. The page refreshes
every 20 seconds and has a light and a dark theme.

To keep the dashboard running in the background with pm2:

```bash
pm2 start ecosystem.config.js   # from the repo folder; edit the interpreter path if needed
pm2 save
```

How web apps are detected: the dashboard sends one `GET /` to each listening port on this machine, waiting at
most 0.8 s. If the page redirects to another path in the same app, such as `/login`, it follows that to read the
title. Windows RPC and SMB ports are never probed. Results are cached until the process on a port changes.

## Your registry and settings

- **`~/.port-checker/Ports.md`:** plain markdown tables (*Registered*, *Transient*, *Reserved*), so you can read
  and edit it by hand too. To keep it somewhere else, such as a notes vault or a synced folder, set `ports_md` in
  the config.
- **`~/.port-checker/config.json`:** overrides the packaged defaults (`portchecker/defaults.json`):

```json
{
  "ports_md": "~/notes/Ports.md",
  "pools": {
    "app":  {"start": 8100, "end": 8999, "section": "registered"},
    "web":  {"start": 3000, "end": 3999, "section": "registered"}
  },
  "loopback_only_sections": ["registered"],
  "ignore": [{"process": "Dropbox", "reason": "sync app, not mine"}]
}
```

`pools` replaces the default pools. `ignore` adds to the default list, which already covers the common OS
processes on Windows, macOS and Linux. Set `PORTS_HOME` to move the whole folder.

## Platforms

| OS | Listeners | Process names and parents |
|---|---|---|
| Windows | `netstat -ano` (works whatever language Windows uses), `netsh` excluded ranges | one PowerShell CIM call |
| Linux | `/proc/net/tcp*`, `/proc/net/udp*` (no extra tools) | `/proc/<pid>/stat` |
| macOS | `lsof` | `ps` |

On Linux and macOS, other users' processes (for example root services) show up with pid `0` and owner `?`.
Run with `sudo` to see their owners.

The macOS backend is covered by the unit tests but has not yet been run on a real Mac. Please open an issue if
something looks wrong.

## Privacy

Everything stays on your machine. Some data never leaves `portchecker/pm.py`:
- pm2's environment blocks, which often hold API keys, are read but only the app name, pid, status, working
  folder and port are kept;
- a test checks that no secret gets through.

The dashboard binds to 127.0.0.1 only and has no write actions.

## Development

```bash
python -m unittest discover -s tests -t .
```

## Licence

MIT
