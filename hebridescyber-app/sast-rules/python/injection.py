# Annotated test cases for injection.yaml (run: opengrep test sast-rules/).
import os
import shlex
import subprocess
import sqlite3

import pandas as pd
from django.db.models.expressions import RawSQL
from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)
conn = sqlite3.connect("app.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cursor = conn.cursor()
    # ruleid: py-sql-injection
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    # ruleid: py-sql-injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: py-sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % request.form["name"])
    # ok: py-sql-injection
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    # ok: py-sql-injection
    cursor.execute("SELECT * FROM users WHERE id = %d" % int(user_id))
    # ok: py-sql-injection
    cursor.execute("SELECT COUNT(*) FROM users")
    return "ok"


@app.route("/graphql", methods=["POST"])
def graphql_view():
    # A GraphQL schema's execute() is not SQL.
    # ok: py-sql-injection
    return schema.execute(request.json["query"])


def django_view(request):
    term = request.GET.get("q")
    # ruleid: py-sql-injection-raw-query
    people = Person.objects.raw("SELECT * FROM people WHERE name = '%s'" % term)
    # ok: py-sql-injection-raw-query
    people = Person.objects.raw("SELECT * FROM people WHERE name = %s", [term])
    # ruleid: py-sql-injection-raw-query
    qs = Person.objects.annotate(v=RawSQL("SELECT " + term, ()))
    # ruleid: py-sql-injection-raw-query
    frame = pd.read_sql("SELECT * FROM t WHERE c = '" + term + "'", conn)
    # ruleid: py-sql-injection-raw-query
    rows = session.execute(text(f"SELECT * FROM t WHERE c = '{term}'"))
    # ok: py-sql-injection-raw-query
    rows = session.execute(text("SELECT * FROM t WHERE c = :c"), {"c": term})
    return people, qs, frame, rows


@app.route("/calc")
def calc():
    # ruleid: py-code-injection
    return str(eval(request.args["expr"]))


@app.route("/run", methods=["POST"])
def run_snippet():
    snippet = request.get_json()["code"]
    # ruleid: py-code-injection
    exec(snippet)
    # ok: py-code-injection
    exec("print('hello')")
    return "ok"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # ruleid: py-command-injection-subprocess-shell
    subprocess.run("ping -c 1 " + host, shell=True)
    # ruleid: py-command-injection-subprocess-shell
    subprocess.check_output(f"nslookup {host}", shell=True, text=True)
    # ok: py-command-injection-subprocess-shell
    subprocess.run(["ping", "-c", "1", host])
    # ok: py-command-injection-subprocess-shell
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)
    # ok: py-command-injection-subprocess-shell
    subprocess.run("uptime", shell=True)
    return "ok"


@app.route("/disk")
def disk():
    path = request.args.get("path")
    # ruleid: py-command-injection-os-system
    os.system("du -sh " + path)
    # ruleid: py-command-injection-os-system
    out = os.popen("ls " + path).read()
    # ok: py-command-injection-os-system
    os.system("du -sh " + shlex.quote(path))
    # ok: py-command-injection-os-system
    os.system("df -h")
    return out
