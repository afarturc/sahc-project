# SAHC bench results

Target: `127.0.0.1:7878`

## Handshake latency

End-to-end client_session_open + client_session_close, 50 iterations.

| metric | ms |
|---|---|
| mean | 3.20 |
| p50  | 3.10 |
| p95  | 3.66 |
| p99  | 8.19 |
| min  | 2.35 |
| max  | 8.19 |

## Upload throughput vs batch size

One open session, 5 uploads per batch size. Latency is per upload, throughput is records/s based on mean latency.

| batch | mean ms | p95 ms | records/s | KB/s |
|---|---|---|---|---|
| 1 | 3.29 | 3.96 | 304 | 5.9 |
| 5 | 3.47 | 4.14 | 1440 | 28.1 |
| 25 | 2.89 | 3.89 | 8650 | 168.9 |
| 100 | 2.72 | 3.80 | 36738 | 717.5 |

## Query latency

Five aggregate queries, 20 iterations each. Per-query latency, researcher role.

| query | mean ms | p50 ms | p95 ms | matched |
|---|---|---|---|---|
| AVG age (any) | 0.24 | 0.22 | 0.35 | 655 |
| MIN temp (any) | 0.09 | 0.09 | 0.14 | 655 |
| MAX blood_sugar (diabetes) | 0.08 | 0.08 | 0.09 | 170 |
| COUNT age (hypertension) | 0.09 | 0.08 | 0.10 | 148 |
| AVG blood_sugar (any) | 0.09 | 0.09 | 0.11 | 655 |

