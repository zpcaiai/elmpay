
# SLO 模板

| SLI | 建议初始目标 | 失败处理 |
|---|---:|---|
| Payment Intent API availability | 99.95% monthly | error budget freeze |
| Verified webhook durable ingest | 99.99% | immediate incident |
| Payment status convergence p99 | provider-specific | active query/reconciliation |
| Duplicate financial effect | 0 | severity 1 |
| Ledger imbalance | 0 | stop writes and investigate |
| Unexplained daily reconciliation delta | 0 above materiality | finance incident |
| Admin phishing-resistant MFA coverage | 100% privileged users | revoke access |
| Backup restore success | 100% scheduled drills | release block |

目标必须按业务量、渠道 SLA 和地区调整；不能用平均值掩盖高价值交易失败。
