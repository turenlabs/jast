# Offline Context Packing Audit

Compared the user's JAST v0.2 export against v0.3 inventory/request generation.
No API requests were made and the original repository was not accessed. Only the
499 files represented in the export were reconstructed into a temporary directory;
every overlapping line was checked for equality and gaps were rejected.

| Measure | v0.2 Export | v0.3 Prepared Requests |
| --- | --- | --- |
| Included files | 499 | 499 |
| Regions | 1,000 | 595 |
| Total request bytes | 27,252,524 | 13,119,834 |
| Question-object bytes | 20,759,000 | 6,314,735 |
| Recorded API input tokens | 5,874,836 | Not measured (no API calls) |
| Files lost from exported scope | n/a | 0 |

The prepared workload uses 40.5% fewer regions and approximately 51.9% fewer
request bytes. This combines whole-file-first packing, shared native guidance and
updated review instructions; it is not a controlled accuracy comparison.

The reconstructed unique source is 5,308,244 bytes. Encoding each file as base64
would produce 7,078,300 ASCII bytes, about 33.3% more, before JSON or tokenization.
Base64 was not sent to a model; no token or quality claim is inferred from bytes.

The original scan was at the 1,000-region cap and did not export its exclusions.
This audit cannot recover omitted files, prove coverage of the whole repository,
or determine whether new context fixes any of the four reported candidates.
The audit's `limit_reached=false` describes only these reconstructed files, not
the full original repository.
