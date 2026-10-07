# SAINT common finding schema

Every normalizer (`normalize_nmap.py`, `normalize_burp.py`, ZAP's own output,
and manual PoC files) produces a JSON file shaped like this:

```json
{
  "source": "nmap | zap | burp | manual_poc",
  "target_name": "string, matches a name in config/targets.yaml",
  "generated_at": "ISO 8601 timestamp (optional for manual files)",
  "finding_count": 0,
  "findings": [
    {
      "id": "unique string, unique within its source",
      "source": "nmap | zap | burp | manual_poc",
      "target_name": "string",
      "host": "string - IP, URL, or URL+path",
      "title": "short human-readable title",
      "description": "longer free-text description",
      "severity": "Critical | High | Medium | Low | Informational",
      "owasp_category": "string or null - filled in by the aggregator",
      "evidence": { "...": "source-specific key/value details" },
      "confirmed": true,
      "scanner_raw_ref": "path or label pointing back to raw tool output"
    }
  ]
}
```

## Why this shape

- `source` + `id` together give a stable dedup key.
- `severity` is normalized to one 5-point scale across tools, since Nmap has
  no concept of severity, ZAP uses Risk levels, and Burp uses its own
  severity field.
- `confirmed` distinguishes "a scanner flagged this" from "this was manually
  verified exploitable" (see `output/manual_poc/`), which matters a lot when
  you're explaining the report later -- scanner findings can have false
  positives, manual PoC findings generally don't.
- `owasp_category` is left `null` by the individual normalizers and filled in
  by `aggregator.py` using the keyword-based mapping in
  `config/report_config.yaml`. Centralizing that logic in one place means you
  only have to maintain the mapping rules once.

## Adding a new source later

To plug in another tool (e.g. Nikto, testssl.sh, trivy for container/image
scanning), write a `normalize_<tool>.py` that emits this same shape and drop
its output JSON in `output/<tool>/`. The aggregator globs every `*.json`
under `output/*/` that matches this schema, so no aggregator changes are
needed for a well-behaved normalizer.
