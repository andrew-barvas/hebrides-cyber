// Annotated test cases for code-injection.yaml (run: opengrep test sast-rules/).
const vm = require("vm");
const { runInNewContext } = require("vm");

app.post("/calc", (req, res) => {
  // ruleid: js-code-injection
  const result = eval(req.body.expression);
  res.json({ result });
});

app.get("/filter", (req, res) => {
  const body = "return item." + req.query.field + " > 10";
  // ruleid: js-code-injection
  const fn = new Function("item", body);
  res.json(items.filter(fn));
});

app.get("/safe-json", (req, res) => {
  // ok: js-code-injection
  const data = JSON.parse(req.query.data);
  res.json(data);
});

app.get("/safe-constant", (req, res) => {
  // ok: js-code-injection
  const two = eval("1 + 1");
  res.json({ two, q: req.query.q });
});

app.get("/safe-stringify", (req, res) => {
  // ok: js-code-injection
  const v = eval("(" + JSON.stringify(req.query.v) + ")");
  res.json(v);
});

app.post("/template", (req, res) => {
  // ruleid: js-code-injection-vm
  const out = vm.runInNewContext(req.body.template, { user: req.user });
  // ruleid: js-code-injection-vm
  const out2 = runInNewContext("`" + req.body.tpl + "`", {});
  // ruleid: js-code-injection-vm
  const script = new vm.Script(req.body.code);
  // ok: js-code-injection-vm
  const fixed = vm.runInNewContext("a + b", { a: Number(req.body.a), b: 2 });
  res.json({ out, out2, script, fixed });
});
