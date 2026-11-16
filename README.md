# ledgerline-policies
Cedarling policy store for the Ledgerline research MCP server (ledger-demo)

## Proof bundles

`tools/make_proof_bundle.py` builds a `cedarling-trace-proof/1` bundle for one decision stored in Lock, so it can be checked at https://cedarling.dev/playground/proof.

```bash
export TRACE_READ_TOKEN=...   # scope https://jans.io/oauth/lock/trace.readonly
export TRACE_ADMIN_TOKEN=...  # scope https://jans.io/oauth/lock/trace.admin
python3 tools/make_proof_bundle.py \
  --lock https://ledger-demo.gluu.info \
  --execution-id exec-... \
  --cjar https://github.com/mzico/ledgerline-policies/releases/download/ledgerline_research_mcp-v0.1.1/ledgerline_research_mcp.cjar \
  --release-tag ledgerline_research_mcp-v0.1.1 \
  --out proof.json
```

It refuses a `.cjar` whose SHA-256 differs from the record's `bundle_hash`. With `cryptography` installed it also checks the signature locally.
