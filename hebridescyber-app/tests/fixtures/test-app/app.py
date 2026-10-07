# Deliberately vulnerable local test app for the tool-integration CI job
# (.github/workflows/tool-integration.yml). It exists so sqlmap and xsser can
# be run against a target we own and their real output checked. Binds to
# 127.0.0.1 only; never deploy it.
#   /item?id=N   builds its SQL by string concatenation (SQL injection)
#   /search?q=   reflects q unescaped (reflected XSS)
#   /static/app.js  names API paths, an S3 bucket and a third-party script,
#                   for gospider's JavaScript endpoint discovery
#   /  carries a <title>, for httpx's live-host title/tech probing
import sqlite3, http.server, urllib.parse
db=sqlite3.connect(":memory:",check_same_thread=False)
db.execute("create table items(id integer, name text)")
db.executemany("insert into items values(?,?)",[(1,"alpha"),(2,"beta"),(3,"gamma")])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        u=urllib.parse.urlparse(self.path); q=urllib.parse.parse_qs(u.query)
        if u.path=="/":
            body="<html><head><title>Test App Home</title></head><body><a href='/item?id=1'>item</a><form action='/search' method='get'><input name='q'><input type=submit></form><script src='/static/app.js'></script></body></html>"
        elif u.path=="/api/health":
            body='{"status":"ok"}'  # an API route kiterunner's wordlist can discover (200)
        elif u.path=="/api/admin":
            self.send_response(401); self.send_header("content-type","application/json"); self.end_headers(); self.wfile.write(b'{"error":"unauthorized"}'); return
        elif u.path=="/static/app.js":
            js="fetch('/api/v1/users');\nvar admin='/api/internal/admin/export';\nvar img='https://acme-uploads.s3.amazonaws.com/a.png';\nvar lib='https://cdn.example.org/lib.js';\n"
            self.send_response(200); self.send_header("content-type","application/javascript"); self.end_headers(); self.wfile.write(js.encode()); return
        elif u.path=="/item":
            try:
                rows=db.execute("select name from items where id="+q.get("id",["0"])[0]).fetchall()
                body="<html><body>"+",".join(r[0] for r in rows)+"</body></html>"
            except Exception as e:
                body="<html><body>SQL error: %s</body></html>"%e
        elif u.path=="/search":
            body="<html><body>Results for: "+q.get("q",[""])[0]+"</body></html>"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("content-type","text/html"); self.end_headers(); self.wfile.write(body.encode())
http.server.ThreadingHTTPServer(("127.0.0.1",int(__import__("os").environ.get("PORT","8099"))),H).serve_forever()
