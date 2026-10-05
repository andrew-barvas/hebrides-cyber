# Annotated test cases for open-redirect.yaml (run: opengrep test sast-rules/).
from django.http import HttpResponseRedirect
from django.shortcuts import redirect as django_redirect
from django.utils.http import url_has_allowed_host_and_scheme
from flask import Flask, redirect, request, url_for

app = Flask(__name__)


@app.route("/login/callback")
def callback():
    # ruleid: py-open-redirect
    return redirect(request.args.get("next"))


@app.route("/safe-route")
def safe_route():
    # ok: py-open-redirect
    return redirect(url_for("profile", tab=request.args.get("tab")))


@app.route("/safe-prefix")
def safe_prefix():
    # ok: py-open-redirect
    return redirect("/search?q=" + request.args.get("q"))


def django_login(request):
    target = request.GET.get("next", "/")
    # ruleid: py-open-redirect
    return HttpResponseRedirect(target)


def django_login_checked(request):
    target = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        target = "/"
    # ok: py-open-redirect
    return django_redirect(target)
