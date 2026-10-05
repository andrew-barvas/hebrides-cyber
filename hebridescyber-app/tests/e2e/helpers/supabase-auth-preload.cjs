// Loaded into the Next server via NODE_OPTIONS (see playwright.config.ts).
//
// Why this exists: src/middleware.ts calls supabase.auth.getUser() on the
// SERVER for every /dashboard, /account and /admin request. That request goes
// from the Next process to https://example-project.supabase.co, which
// page.route() cannot intercept (it only sees browser traffic). Without this,
// a signed-in test can never get past the middleware redirect to /login.
//
// Middleware runs in Next's Edge runtime sandbox, which has its own bundled
// fetch (undici) that ignores a patched globalThis.fetch. What it does share
// with the host is Node's `tls` module, so we intercept tls.connect() for the
// one fake host and point it at a tiny local HTTP server instead. The server
// answers only GET /auth/v1/user, and only for the unsigned test JWT minted by
// helpers/session.ts (its `iss` is "e2e-test"); everything else gets 404. No
// other host is touched and nothing real is contacted. It never runs in
// production: only the Playwright webServer sets NODE_OPTIONS.
const http = require("node:http");
const net = require("node:net");
const tls = require("node:tls");

const HOST = "example-project.supabase.co";

function userFromBearer(authorization) {
  const token = (authorization || "").replace(/^Bearer\s+/i, "");
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] || "", "base64url").toString("utf8"));
    if (payload.iss !== "e2e-test") return null;
    if (payload.exp && payload.exp * 1000 < Date.now()) return null;
    return {
      id: payload.sub,
      aud: "authenticated",
      role: "authenticated",
      email: payload.email,
      app_metadata: {},
      user_metadata: {},
      created_at: "2026-01-01T00:00:00Z",
    };
  } catch {
    return null;
  }
}

const server = http.createServer((req, res) => {
  const send = (status, body) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  if (req.method === "GET" && req.url.split("?")[0] === "/auth/v1/user") {
    const user = userFromBearer(req.headers.authorization);
    return user ? send(200, user) : send(401, { message: "invalid JWT" });
  }
  return send(404, { message: "not mocked by the e2e preload" });
});
server.listen(0, "127.0.0.1");
server.unref();

const realConnect = tls.connect;
tls.connect = function patchedConnect(...args) {
  const opts = args[0];
  if (opts && typeof opts === "object" && (opts.host === HOST || opts.servername === HOST)) {
    const socket = net.connect({ host: "127.0.0.1", port: server.address().port });
    // The caller waits for the TLS handshake event; a plain socket has none.
    socket.once("connect", () => socket.emit("secureConnect"));
    return socket;
  }
  return realConnect.apply(this, args);
};
