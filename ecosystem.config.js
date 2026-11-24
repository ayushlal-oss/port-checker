// pm2: keep the read-only port dashboard running on 127.0.0.1:8801.
//   pm2 start ecosystem.config.js && pm2 save
// Set PORTS_PYTHON to a full interpreter path if "pythonw"/"python3" is not on your PATH.
// On Windows, pythonw (not python) avoids an empty console window that would kill the app when closed.
const python = process.env.PORTS_PYTHON || (process.platform === "win32" ? "pythonw" : "python3");

module.exports = {
  apps: [{
    name: "port-checker",
    cwd: __dirname,
    script: "serve.py",
    args: "8801",
    interpreter: python,
    autorestart: true, max_restarts: 10, restart_delay: 2000,
    windowsHide: true,
    env: { PYTHONUNBUFFERED: "1", PORTS_REFRESH: "20" },
  }],
};
