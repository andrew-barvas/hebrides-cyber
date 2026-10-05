// Annotated test cases for deserialization.yaml (run: opengrep test sast-rules/).
const serialize = require("node-serialize");

app.get("/profile", (req, res) => {
  const raw = Buffer.from(req.cookies.profile, "base64").toString();
  // ruleid: js-unsafe-deserialization
  const profile = serialize.unserialize(raw);
  res.json(profile);
});

app.get("/safe-json", (req, res) => {
  // ok: js-unsafe-deserialization
  const profile = JSON.parse(req.cookies.profile);
  res.json(profile);
});

app.get("/safe-constant", (req, res) => {
  // ok: js-unsafe-deserialization
  const defaults = serialize.unserialize('{"theme":"dark"}');
  res.json({ defaults, q: req.query.q });
});
