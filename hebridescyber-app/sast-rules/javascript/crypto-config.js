// Annotated test cases for crypto-config.yaml (run: opengrep test sast-rules/).
const https = require("https");
const jwt = require("jsonwebtoken");

// ruleid: js-tls-verification-disabled
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// ruleid: js-tls-verification-disabled
request.get({ url: "https://partner.example/api", strictSSL: false }, cb);

// ok: js-tls-verification-disabled
const agent = new https.Agent({ rejectUnauthorized: true, ca: privateCa });

// ok: js-tls-verification-disabled
const devAgent = new https.Agent({ rejectUnauthorized: process.env.NODE_ENV === "production" });

if (process.env.NODE_ENV === "development") {
  // ok: js-tls-verification-disabled
  localAgent = new https.Agent({ rejectUnauthorized: false });
}

// ruleid: js-tls-verification-disabled-env
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// ok: js-tls-verification-disabled-env
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";

function verifyToken(token) {
  // ruleid: js-jwt-none-algorithm
  return jwt.verify(token, secret, { algorithms: ["HS256", "none"] });
}

function issueToken(user) {
  // ruleid: js-jwt-none-algorithm
  return jwt.sign({ sub: user.id }, "", { algorithm: "none" });
}

function verifyTokenSafely(token) {
  // ok: js-jwt-none-algorithm
  return jwt.verify(token, secret, { algorithms: ["HS256"] });
}
