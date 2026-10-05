// Annotated test cases for command-injection.yaml (run: opengrep test sast-rules/).
const cp = require("child_process");
const { exec, execSync, spawn, execFile } = require("child_process");
const util = require("util");
const execAsync = util.promisify(cp.exec);
const shell = require("shelljs");

app.get("/ping", (req, res) => {
  // ruleid: js-command-injection
  cp.exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/convert", (req, res) => {
  const file = req.body.file;
  // ruleid: js-command-injection
  execSync(`convert ${file} out.png`);
});

app.post("/archive", async (req, res) => {
  // ruleid: js-command-injection
  await execAsync("tar czf backup.tgz " + req.body.dir);
});

app.get("/shelljs", (req, res) => {
  // ruleid: js-command-injection
  shell.exec("git log " + req.query.ref);
});

app.get("/safe-execfile", (req, res) => {
  // ok: js-command-injection
  execFile("ping", ["-c", "1", req.query.host], (err, out) => res.send(out));
});

app.get("/safe-constant", (req, res) => {
  // ok: js-command-injection
  exec("uptime", (err, out) => res.send(out));
});

app.get("/regex-exec", (req, res) => {
  // RegExp.prototype.exec is not a shell.
  // ok: js-command-injection
  const m = /^(\d+)$/.exec(req.query.id);
  res.send(m);
});

app.get("/safe-int", (req, res) => {
  const n = parseInt(req.query.n, 10);
  // ok: js-command-injection
  exec("seq " + n);
});

app.get("/spawn-shell", (req, res) => {
  // ruleid: js-command-injection-shell-option
  spawn("grep " + req.query.pattern + " /var/log/app.log", { shell: true });
  // ruleid: js-command-injection-shell-option
  cp.spawn("ls", [req.query.dir], { shell: true });
  // ruleid: js-command-injection-shell-option
  spawn("sh", ["-c", "ls " + req.query.dir]);
  // ok: js-command-injection-shell-option
  spawn("ls", [req.query.dir]);
  // ok: js-command-injection-shell-option
  spawn("ls", [req.query.dir], { shell: false });
  // ok: js-command-injection-shell-option
  spawn("ls", ["-la"], { shell: true });
});
