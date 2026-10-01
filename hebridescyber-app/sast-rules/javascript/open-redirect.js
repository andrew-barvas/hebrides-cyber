// Annotated test cases for open-redirect.yaml (run: opengrep test sast-rules/).
app.get("/login/callback", (req, res) => {
  // ruleid: js-open-redirect
  res.redirect(req.query.next);
});

app.get("/out", (req, res) => {
  const target = req.query.url;
  // ruleid: js-open-redirect
  res.redirect(302, target);
});

app.get("/go", (req, res) => {
  // ruleid: js-open-redirect
  res.setHeader("Location", req.query.to);
  res.statusCode = 302;
  res.end();
});

app.get("/safe-prefix", (req, res) => {
  // ok: js-open-redirect
  res.redirect("/login?next=" + req.query.next);
});

app.get("/safe-encoded", (req, res) => {
  // ok: js-open-redirect
  res.redirect("/search?q=" + encodeURIComponent(req.query.q));
});

app.get("/safe-checked", (req, res) => {
  const next = req.query.next;
  if (!isSafeRedirect(next)) return res.redirect("/");
  // ok: js-open-redirect
  res.redirect(next);
});

app.get("/safe-allowlist", (req, res) => {
  const next = req.query.next;
  if (!ALLOWED_TARGETS.includes(next)) return res.sendStatus(400);
  // ok: js-open-redirect
  res.redirect(next);
});

app.get("/https-upgrade", (req, res) => {
  // The Host header is not attacker-controllable through a link.
  // ok: js-open-redirect
  res.redirect("https://" + req.headers.host + req.url);
});

export async function GET(request) {
  const next = request.nextUrl.searchParams.get("next");
  // ruleid: js-open-redirect
  return NextResponse.redirect(next);
}
