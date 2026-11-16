#!/usr/bin/env python3
"""Build a cedarling-trace-proof/1 bundle from a Janssen Lock server.

The bundle holds one signed AUTHORIZATION_DECISION record, the producer's
public key and the released .cjar, so anyone can check it at
https://cedarling.dev/playground/proof without access to Lock.

Tokens are read from the environment and never printed:
  TRACE_READ_TOKEN   access token with https://jans.io/oauth/lock/trace.readonly
  TRACE_ADMIN_TOKEN  access token with https://jans.io/oauth/lock/trace.admin
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

FORMAT = "cedarling-trace-proof/1"
MAX_CJAR_BYTES = 5 * 1024 * 1024


def fail(message):
    sys.exit(f"error: {message}")


def get(url, token=None, raw=False):
    if not url.startswith("https://"):
        fail(f"refusing non-https URL {url}")
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(MAX_CJAR_BYTES + 1)
    except urllib.error.HTTPError as error:
        fail(f"GET {url.split('?')[0]} returned {error.code}")
    except urllib.error.URLError as error:
        fail(f"GET {url.split('?')[0]} failed: {error.reason}")
    if len(body) > MAX_CJAR_BYTES:
        fail(f"{url.split('?')[0]} is larger than 5 MiB")
    return body if raw else json.loads(body)


def endpoints(lock):
    config = get(f"{lock.rstrip('/')}/.well-known/lock-server-configuration")
    audit = config.get("audit") or {}
    trace = audit.get("trace_endpoint")
    executions = audit.get("trace_execution_endpoint")
    if not trace or not executions:
        fail("Lock does not advertise TRACE endpoints")
    return trace, executions


def decision_record(executions, token, execution_id, authority):
    query = f"?{urllib.parse.urlencode({'execution_authority': authority})}" if authority else ""
    body = get(f"{executions}/{urllib.parse.quote(execution_id, safe='')}{query}", token)
    records = [
        record
        for record in body.get("records") or []
        if (record.get("assertion") or {}).get("trace", {}).get("event_kind")
        == "AUTHORIZATION_DECISION"
    ]
    if not records:
        fail(f"no AUTHORIZATION_DECISION record for {execution_id}")
    if len(records) > 1:
        print(f"note: {len(records)} decision records, using the first", file=sys.stderr)
    return records[0]


def producer_key(trace, token, producer_id, kid):
    query = urllib.parse.urlencode({"producer_id": producer_id})
    keys = get(f"{trace}/admin/producer-keys?{query}", token).get("keys") or []
    for key in keys:
        if key.get("kid") == kid:
            jwk = key.get("public_key_jwk") or {}
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not jwk.get("x"):
                fail(f"key {kid} is not an Ed25519 OKP key")
            return {
                "producer_id": producer_id,
                "kid": kid,
                "public_jwk": {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]},
                "valid_from": key.get("valid_from"),
                "valid_until": key.get("valid_until"),
            }
    fail(f"Lock lists no key {kid} for producer {producer_id}")


def read_cjar(source):
    if source.startswith("https://"):
        return get(source, raw=True)
    with open(source, "rb") as file:
        data = file.read(MAX_CJAR_BYTES + 1)
    if len(data) > MAX_CJAR_BYTES:
        fail(f"{source} is larger than 5 MiB")
    return data


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def check_signature(assertion, jwk):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return "skipped (pip install cryptography to check here)"
    pad = lambda text: text + "=" * (-len(text) % 4)  # noqa: E731
    unsigned = {key: value for key, value in assertion.items() if key != "signature"}
    public = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(pad(jwk["x"])))
    try:
        public.verify(
            base64.urlsafe_b64decode(pad(assertion["signature"])),
            canonical(unsigned).encode(),
        )
    except InvalidSignature:
        return "INVALID"
    return "valid"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--lock", required=True, help="Lock base URL, e.g. https://ledger-demo.gluu.info")
    parser.add_argument("--execution-id", required=True, help="trace_execution_id of the decision")
    parser.add_argument("--execution-authority", help="execution authority, if Lock needs it")
    parser.add_argument("--cjar", required=True, help="released .cjar: GitHub asset URL or local path")
    parser.add_argument("--release-tag", required=True, help="release tag the .cjar belongs to")
    parser.add_argument("--out", required=True, help="output file")
    args = parser.parse_args()

    read_token = os.environ.get("TRACE_READ_TOKEN")
    admin_token = os.environ.get("TRACE_ADMIN_TOKEN")
    if not read_token or not admin_token:
        fail("set TRACE_READ_TOKEN and TRACE_ADMIN_TOKEN")

    trace, executions = endpoints(args.lock)
    record = decision_record(executions, read_token, args.execution_id, args.execution_authority)
    assertion = record["assertion"]
    if not isinstance(assertion.get("signature"), str):
        fail("record has no signature")
    key = producer_key(trace, admin_token, assertion.get("producer"), assertion.get("kid"))

    cjar = read_cjar(args.cjar)
    digest = "sha256:" + hashlib.sha256(cjar).hexdigest()
    bundle_hash = assertion.get("trace", {}).get("policy", {}).get("bundle_hash")
    if digest != bundle_hash:
        fail(f"the .cjar hashes to {digest}, but the record names {bundle_hash}")

    bundle = {
        "format": FORMAT,
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "assertion": assertion,
        "lock": {
            "verification": record.get("verification") or {},
            "ingestion": record.get("ingestion") or {},
        },
        "producer_key": key,
        "release": {
            "tag": args.release_tag,
            "cjar_sha256": digest,
            "cjar_base64": base64.b64encode(cjar).decode(),
        },
    }
    with open(args.out, "w", encoding="utf-8") as file:
        json.dump(bundle, file, indent=2)
        file.write("\n")

    decision = assertion.get("trace", {}).get("event", {}).get("decision", {})
    print(f"wrote {args.out}")
    print(f"  {decision.get('outcome')} {decision.get('action')} under {bundle_hash}")
    print(f"  signature: {check_signature(assertion, key['public_jwk'])}")


if __name__ == "__main__":
    main()
