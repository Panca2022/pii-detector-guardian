#!/usr/bin/env python3
"""
detector_lalanthika_s.py

Usage:
    python3 detector_lalanthika_s.py iscp_pii_dataset.csv

This script reads a CSV with columns: record_id,Data_json
It outputs: redacted_output_lalanthika_s.csv with columns: record_id,redacted_data_json,is_pii

The deployment proposal (Markdown) is included at the bottom in the DEPLOYMENT_MD variable.

This single-file solution uses only Python standard libraries.
"""

import csv
import json
import re
import sys
from copy import deepcopy

# --- Regex patterns ---
PHONE_RE = re.compile(r"\b(\d{10})\b")
AADHAR_RE = re.compile(r"\b(?:\d{4}\s?\d{4}\s?\d{4}|\d{12})\b")
PASSPORT_RE = re.compile(r"\b[A-Z]{1,2}\d{6,7}\b", re.IGNORECASE)
# UPI id: local@bank or number@bank - treat as standalone PII
UPI_RE = re.compile(r"\b[\w.\-]{1,64}@[a-zA-Z0-9_\-\.]{2,64}\b")
# IP address (combinatorial)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

# --- Helper maskers ---

def mask_phone(s):
    s = str(s)
    m = PHONE_RE.search(s)
    if not m:
        return "[REDACTED_PHONE]"
    v = m.group(1)
    if len(v) == 10:
        return v[:2] + 'XXXXXX' + v[-2:]
    return '[REDACTED_PHONE]'


def mask_aadhar(s):
    s = str(s)
    m = AADHAR_RE.search(s)
    if not m:
        return '[REDACTED_AADHAR]'
    v = re.sub(r"\s+", "", m.group(0))
    return 'XXXXXXXX' + v[-4:]


def mask_passport(s):
    s = str(s)
    m = PASSPORT_RE.search(s)
    if not m:
        return '[REDACTED_PASSPORT]'
    v = m.group(0)
    if len(v) <= 3:
        return 'X' * len(v)
    return v[0] + 'X' * (len(v) - 3) + v[-2:]


def mask_upi(s):
    s = str(s)
    m = UPI_RE.search(s)
    if not m:
        return '[REDACTED_UPI]'
    v = m.group(0)
    if '@' in v:
        local, domain = v.split('@', 1)
        if len(local) <= 2:
            local_masked = local[0] + 'X'
        else:
            local_masked = local[:2] + 'X' * (len(local) - 2)
        return local_masked + '@' + domain
    return '[REDACTED_UPI]'


def mask_email(s):
    s = str(s)
    if '@' not in s:
        return '[REDACTED_EMAIL]'
    local, domain = s.split('@', 1)
    if len(local) <= 2:
        local_masked = local[0] + 'X'
    else:
        local_masked = local[:2] + 'X' * (len(local) - 2)
    return local_masked + '@' + domain


def mask_name_full(name):
    # keep first letter of each name part, mask rest
    if not name or not isinstance(name, str):
        return '[REDACTED_NAME]'
    parts = name.split()
    masked_parts = []
    for p in parts:
        if len(p) == 1:
            masked_parts.append(p)
        else:
            masked_parts.append(p[0] + 'X' * (len(p) - 1))
    return ' '.join(masked_parts)


def mask_address(s):
    return '[REDACTED_ADDRESS]'


def mask_ip(s):
    s = str(s)
    m = IPV4_RE.search(s)
    if not m:
        return '[REDACTED_IP]'
    ip = m.group(0)
    parts = ip.split('.')
    if len(parts) == 4:
        return '.'.join(parts[:3] + ['XXX'])
    return '[REDACTED_IP]'

# --- Detection logic per definitions ---

def detect_standalone_pii(record_values):
    """Return list of standalone pii types detected and map field->value for masking"""
    detected = {}
    # check phone anywhere
    for k, v in record_values.items():
        if v is None:
            continue
        s = str(v)
        if PHONE_RE.search(s):
            detected['phone'] = (k, s)
            break
    # aadhar
    for k, v in record_values.items():
        if v is None:
            continue
        if AADHAR_RE.search(str(v)):
            detected['aadhar'] = (k, str(v))
            break
    # passport
    for k, v in record_values.items():
        if v is None:
            continue
        if PASSPORT_RE.search(str(v)):
            detected['passport'] = (k, str(v))
            break
    # upi id: prefer upi_id key, else search
    if 'upi_id' in record_values and record_values.get('upi_id'):
        detected['upi'] = ('upi_id', str(record_values.get('upi_id')))
    else:
        for k, v in record_values.items():
            if v is None:
                continue
            if UPI_RE.search(str(v)) and ('@' in str(v)):
                # avoid classifying emails as UPI: if key is 'email', skip
                if k.lower() == 'email':
                    continue
                detected['upi'] = (k, str(v))
                break
    return detected


def detect_combinatorial_pii(record_values):
    """Return which combinatorial fields are present among Name, Email, Physical Address, Device/IP"""
    found = {}
    # Name: full name means either 'name' with space or both first_name and last_name present
    name_present = False
    if record_values.get('name') and isinstance(record_values.get('name'), str) and len(record_values.get('name').split()) >= 2:
        name_present = True
        found['name'] = ('name', record_values.get('name'))
    elif record_values.get('first_name') and record_values.get('last_name'):
        name_present = True
        found['name'] = ('first_last', f"{record_values.get('first_name')} {record_values.get('last_name')}")

    # Email
    if record_values.get('email'):
        found['email'] = ('email', str(record_values.get('email')))

    # Physical address: require address + city + pin_code or address containing digits and a pin code pattern
    address_present = False
    if record_values.get('address') and record_values.get('city') and record_values.get('pin_code'):
        found['address'] = ('address', str(record_values.get('address')))
    else:
        addr_val = record_values.get('address')
        pin = record_values.get('pin_code')
        if addr_val and pin:
            found['address'] = ('address', str(addr_val))

    # Device/IP: device_id or ip_address
    if record_values.get('device_id'):
        found['device'] = ('device_id', str(record_values.get('device_id')))
    if record_values.get('ip_address'):
        found['ip'] = ('ip_address', str(record_values.get('ip_address')))

    # Count of unique categories present among name, email, address, device/ip
    categories = 0
    for cat in ('name', 'email', 'address', 'device', 'ip'):
        if cat in found:
            categories += 1
    return found, categories


def redact_record(data_json):
    """Given a parsed JSON dict, return (redacted_dict, is_pii_boolean)"""
    record_values = {k: v for k, v in data_json.items()}
    standalone = detect_standalone_pii(record_values)
    combinatorial_found, comb_count = detect_combinatorial_pii(record_values)

    is_pii = False
    redacted = deepcopy(record_values)

    # If any standalone PII detected -> record is PII
    if standalone:
        is_pii = True
        # redact per type
        for t, (k, val) in standalone.items():
            if t == 'phone':
                redacted[k] = mask_phone(val)
            elif t == 'aadhar':
                redacted[k] = mask_aadhar(val)
            elif t == 'passport':
                redacted[k] = mask_passport(val)
            elif t == 'upi':
                redacted[k] = mask_upi(val)

    # combinatorial rule: if two or more B-type present, it's PII
    if comb_count >= 2:
        is_pii = True
        # redact the detected combinatorial fields
        for cat, (k, val) in combinatorial_found.items():
            if cat == 'name':
                # if name stored as first_name/last_name, mask both
                if k == 'first_last':
                    # handle keys
                    if 'first_name' in redacted:
                        redacted['first_name'] = mask_name_full(redacted.get('first_name', ''))
                    if 'last_name' in redacted:
                        redacted['last_name'] = mask_name_full(redacted.get('last_name', ''))
                else:
                    redacted[k] = mask_name_full(val)
            elif cat == 'email':
                redacted[k] = mask_email(val)
            elif cat == 'address':
                redacted[k] = mask_address(val)
            elif cat == 'device':
                redacted[k] = '[REDACTED_DEVICE_ID]'
            elif cat == 'ip':
                redacted[k] = mask_ip(val)

    # Additional defensive redaction: if record is PII, proactively mask fields that commonly carry PII
    if is_pii:
        # phone keys
        for ph_key in ('phone', 'contact', 'mobile'):
            if ph_key in redacted and redacted[ph_key] is not None:
                redacted[ph_key] = mask_phone(redacted[ph_key])
        # aadhar key
        if 'aadhar' in redacted and redacted['aadhar']:
            redacted['aadhar'] = mask_aadhar(redacted['aadhar'])
        # passport
        if 'passport' in redacted and redacted['passport']:
            redacted['passport'] = mask_passport(redacted['passport'])
        # upi
        if 'upi_id' in redacted and redacted['upi_id']:
            redacted['upi_id'] = mask_upi(redacted['upi_id'])

    return redacted, is_pii


def process_csv(input_csv, output_csv):
    with open(input_csv, newline='', encoding='utf-8') as fin, open(output_csv, 'w', newline='', encoding='utf-8') as fout:
        reader = csv.DictReader(fin)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            rid = row.get('record_id')
            raw_json = row.get('Data_json') or row.get('data_json') or row.get('data')
            try:
                parsed = json.loads(raw_json)
            except Exception:
                # if JSON parsing fails, skip but mark as non-PII and keep original raw
                parsed = {}
            redacted, is_pii = redact_record(parsed)
            writer.writerow({
                'record_id': rid,
                'redacted_data_json': json.dumps(redacted, ensure_ascii=False),
                'is_pii': str(is_pii)
            })


# --- Deployment proposal embedded as a string ---
DEPLOYMENT_MD = r"""
# Deployment proposal — Project Guardian 2.0

## Summary
A hybrid PII detection/redaction system that combines lightweight deterministic rules (regex) with optional NER models for unstructured fields. The detector runs as an API Gateway plugin and as a Sidecar/DaemonSet for internal processing pipelines.

## Placement and rationale
1. **Edge / Ingress (API Gateway plugin)**
   - Where: At the API gateway (e.g., Envoy, Kong, AWS API Gateway) as a plugin/filter.
   - Why: This prevents PII from entering internal systems and external logs. Low latency since work is focused on request/response bodies and headers.
   - Pros: Centralized control, single point to block/sanitize external integrations.
   - Cons: Needs careful tuning to avoid over-blocking; heavier ML models should be optional.

2. **Service Mesh Sidecar (optional)**
   - Where: Sidecar containers (Istio/Linkerd) run inline with services to sanitize East-West traffic, especially for internal integrations and legacy services that cannot integrate with gateway plugins.
   - Why: Captures internal leaks without modifying application code.

3. **DaemonSet for batch / log pipelines**
   - Where: A lightweight DaemonSet (K8s) or log processor (Fluentd/Logstash plugin) that scans logs and redacts PII before they are stored in central logs or sent to observability systems.
   - Why: Many leaks occur through logs; this protects log storage and SIEM.

4. **Developer tools / SDK**
   - A small SDK (Python/Node) provided to developers to do in-process redaction for high-performance, low-latency needs.

## Architecture
- Primary flow: API Gateway plugin -> quick regex checks -> allow/modify request -> if heuristics match for unstructured text, call internal async NER service (optional) with sampled content (not whole payload) -> redact and continue.
- Secondary flow: Sidecar for east-west traffic and DaemonSet for logs.
- Model hosting: Lightweight NER models hosted behind a scalable inference service (K8s HPA) with caching and rate-limits to reduce latency.

## Latency / Scalability
- Keep the in-path gateway/sidecar work deterministic and regex-based (sub-millisecond per field).
- Offload heavy ML-based checks to an out-of-band async pipeline or on-sampled traffic. Use budgeted calls to NER (e.g., 1% of traffic or triggered by heuristics) to keep latency low.

## Cost-effectiveness
- Use open-source models or distilled NER models for inference (CPU-friendly). Cache results for repeated payload shapes.
- Centralized configuration to update rules quickly (feature flags) without redeploys.

## Integration and rollout plan
1. Start with a non-blocking mode on the gateway: plugin logs detections and redactions but does not modify payload (monitor false positives).
2. Move to blocking/redacting mode after tuning (2–4 weeks).
3. Enable Sidecar/DaemonSet gradually for internal teams.

## Logging and Compliance
- Log detection metadata (hashed identifiers, redaction reasons) but never raw PII.
- Maintain an audit trail for redaction decisions with references to rule-IDs and model versions.

## Security
- All PII-handling components must be isolated, encrypted in transit, and authenticated.
- Store only redacted data in long-term storage. If temporary unredacted data is needed for debugging, require secure access and short TTL.

## Conclusion
A layered strategy (Gateway + Sidecar + DaemonSet + SDK) balances latency, coverage, and developer ergonomics while containing cost by only applying heavy ML detection when needed.

"""


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 detector_lalanthika_s.py iscp_pii_dataset.csv")
        sys.exit(2)
    input_csv = sys.argv[1]
    output_csv = 'redacted_output_lalanthika_s.csv'
    process_csv(input_csv, output_csv)
    print(f"Wrote redacted output to: {output_csv}")
    # Write deployment markdown to a companion file for convenience
    with open('PII_deployment_proposal.md', 'w', encoding='utf-8') as f:
        f.write(DEPLOYMENT_MD)
    print("Wrote deployment proposal to: PII_deployment_proposal.md")
