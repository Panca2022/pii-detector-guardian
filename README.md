
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

