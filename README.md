# Threat Intelligence Aggregator

A zero-dependency Python CLI tool and library that pulls, correlates, and scores live Indicators of Compromise (IoCs) across the [VirusTotal API v3](https://docs.virustotal.com/reference/overview) and the [AlienVault Open Threat Exchange (OTX) DirectConnect API v1](https://dlthub.com/context/source/alienvault-open-threat-exchange-otx).

Built for SOC analysts, threat hunters, and detection engineers who need fast, scriptable multi-source enrichment without heavy third-party SDK dependencies.

## Key Features

- **Automatic IoC Classification & Refanging**: Normalizes defanged indicators (`hxxps://`, `[.]`, `[:]`) and automatically classifies IPv4, IPv6, domains, URLs, and file hashes (`MD5`, `SHA-1`, `SHA-256`).
- **Multi-Source Telemetry Correlation**: Combines multi-engine antivirus detections, ASN/GeoIP metadata, and reputation scores from [VirusTotal IP Reports](https://docs.virustotal.com/reference/ip-info) and [VirusTotal Domain Reports](https://docs.virustotal.com/reference/domain-info) with community threat pulses, malware family attributions, and adversary tags from [AlienVault OTX Indicator Endpoints](https://docs.fortinet.com/document/fortisoar/1.0.3/alienvault-otx/1085/alienvault-otx-v1-0-3).
- **Live OTX Pulse Feed Ingestion**: Pulls newly published indicators directly from your subscribed feeds via the [OTX Subscribed Pulses Endpoint](https://docs.eclecticiq.com/extensions/current/integrations/alienvault/incoming-alienvault-otx-pulse/) (`/api/v1/pulses/subscribed`) and cross-checks them against VirusTotal.
- **Built-In Rate Limiting & Backoff**: Enforces configurable request pacing (defaulting to the public [VirusTotal 4-requests-per-minute quota](https://www.rdocumentation.org/packages/virustotal/versions/0.7.0)) and exponential backoff for transient `HTTP 429` and `5xx` responses.
- **Local SQLite Response Caching**: Caches API responses locally (`.threat_intel_cache.sqlite`) with a configurable TTL to prevent duplicate lookups and preserve daily API quotas.
- **Unified Risk Scoring (`0–100`)**: Synthesizes engine hit ratios, community pulse counts, reputation scores, and attributed malware families into a single numeric score and categorical verdict (`MALICIOUS`, `SUSPICIOUS`, `CLEAN`, `UNKNOWN`).
- **Flexible Export Formats**: Outputs human-readable CLI summary tables alongside structured JSON and flattened CSV files ready for SIEM/SOAR ingestion.

## Architecture & Enrichment Pipeline

```text
Input IoCs (-i / -f / --pull-pulses)
       │
       ▼
┌─────────────────────────────────────────┐
│ IoC Normalizer & Classifier             │
│ • Refangs hxxps://, [.], [:]            │
│ • Detects IPv4/v6, Domain, URL, Hashes  │
└──────┬───────────────────────────┬──────┘
       │                           │
       ▼                           ▼
┌──────────────────────┐   ┌──────────────────────────┐
│ VirusTotal API v3    │   │ AlienVault OTX API v1    │
│ • Token-bucket pace  │   │ • General indicator data │
│ • SQLite TTL cache   │   │ • Subscribed pulse feeds │
└──────┬───────────────┘   └───────┬──────────────────┘
       │                           │
       └─────────────┬─────────────┘
                     ▼
┌─────────────────────────────────────────┐
│ Risk Scoring & Aggregation Engine       │
│ • Computes 0–100 composite risk score   │
│ • Assigns MALICIOUS/SUSPICIOUS/CLEAN    │
└──────┬─────────────┬─────────────┬──────┘
       ▼             ▼             ▼
   CLI Table    JSON Report   CSV Export
```

## Requirements & Installation

`threat_intel_aggregator.py` uses only the Python 3.8+ standard library (`urllib`, `sqlite3`, `ipaddress`, `dataclasses`, `csv`, `json`), so no `pip install` step is required.

```bash
git clone https://github.com/your-username/threat-intel-aggregator.git
cd threat-intel-aggregator
chmod +x threat_intel_aggregator.py
```

### Configuring API Keys

Obtain a free or premium API key from the [VirusTotal API v3 Portal](https://docs.virustotal.com/reference/overview) and the [AlienVault OTX Portal](https://otx.alienvault.com/), then export them as environment variables:

```bash
export VT_API_KEY="your_virustotal_api_key"
export OTX_API_KEY="your_alienvault_otx_api_key"
```

## Usage Examples

### 1. Enrich Specific Indicators (Supports Defanged Input)

```bash
python3 threat_intel_aggregator.py -i 185.220.101[.]34 login-micros0ft-security-update[.]com 8.8.8.8
```

### 2. Pull Live IoCs from Subscribed AlienVault OTX Pulses

Fetch the latest indicators from your subscribed OTX pulses, enrich each indicator across both APIs, and export the results to JSON and CSV:

```bash
python3 threat_intel_aggregator.py --pull-pulses --pulse-limit 5 --max-pulse-iocs 20 \
  --output-json reports/latest_pulses.json \
  --output-csv reports/latest_pulses.csv
```

### 3. Batch-Enrich Indicators from a File

Create a text file (`indicators.txt`) with one indicator per line (`#` comments are ignored):

```bash
python3 threat_intel_aggregator.py -f indicators.txt --output-csv enriched_iocs.csv
```

### 4. Run Offline Demo Mode (No API Keys Required)

Preview the scoring engine, CLI table layout, and export schemas using realistic simulated telemetry:

```bash
python3 threat_intel_aggregator.py --demo --output-json demo_report.json --output-csv demo_report.csv
```

**Sample Console Output:**

```text
------------------------------------------------------------------------------------------------------------------------
INDICATOR                              | TYPE    | VERDICT    | RISK |  VT HITS | OTX PULSES | COUNTRY | FAMILIES / TAGS
------------------------------------------------------------------------------------------------------------------------
185.220.101.34                         | ipv4    | MALICIOUS  |  100 |    14/94 |         19 | DE      | Mirai, CobaltStrike, c2, scanner
275a021bbfb6489e54d471899f7db9d1663... | sha256  | MALICIOUS  |  100 |    66/72 |          8 | N/A     | LockBit, RedLine Stealer, eicar, payload
login-micros0ft-security-update.com    | domain  | MALICIOUS  |  100 |     9/92 |          4 | N/A     | EvilProxy, aitm, credential-harvesting, m365
8.8.8.8                                | ipv4    | CLEAN      |    0 |     0/94 |          0 | US      | benign, dns-resolver, google-dns
------------------------------------------------------------------------------------------------------------------------
```

## Command-Line Arguments

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-i`, `--indicators` | One or more space-separated IoCs (IPs, domains, URLs, MD5/SHA1/SHA256 hashes) | `None` |
| `-f`, `--input-file` | Path to a text file containing one IoC per line | `None` |
| `--pull-pulses` | Fetch live IoCs from subscribed AlienVault OTX threat pulses | `False` |
| `--pulse-limit` | Number of recent subscribed OTX pulses to inspect when `--pull-pulses` is set | `5` |
| `--max-pulse-iocs` | Maximum number of unique IoCs to extract from fetched OTX pulses | `20` |
| `--vt-api-key` | VirusTotal API v3 key (falls back to `VT_API_KEY` environment variable) | `env:VT_API_KEY` |
| `--otx-api-key` | AlienVault OTX API v1 key (falls back to `OTX_API_KEY` environment variable) | `env:OTX_API_KEY` |
| `--vt-rate-limit` | VirusTotal requests-per-minute cap (`4` for public tier; `0` for unlimited) | `4` |
| `--cache-ttl` | Local SQLite cache TTL in seconds (`0` disables caching) | `3600` |
| `--output-json` | File path to export the full nested JSON threat intelligence report | `None` |
| `--output-csv` | File path to export flattened summary rows as CSV | `None` |
| `--demo` | Run offline with simulated VirusTotal v3 and AlienVault OTX v1 responses | `False` |

## Risk Scoring Methodology

The aggregator calculates a composite score between `0` and `100` by combining signals from both providers:

| Signal Source | Condition | Points Added |
| :--- | :--- | :--- |
| **VirusTotal Malicious Detections** | `>= 10` security vendors flag the indicator as malicious | `+70` |
| **VirusTotal Malicious Detections** | `3–9` security vendors flag the indicator as malicious | `+50` to `+69` |
| **VirusTotal Malicious Detections** | `1–2` security vendors flag the indicator as malicious | `+25` to `+37` |
| **VirusTotal Community Reputation** | Community reputation score `< -10` | Up to `+15` |
| **AlienVault OTX Pulse Volume** | Indicator appears in `>= 10` community pulses (`+35`), `3–9` pulses (`+22`), or `1–2` pulses (`+12`) | `+12` to `+35` |
| **AlienVault OTX Attribution** | Indicator is linked to a known malware family or threat adversary | `+10` |

### Verdict Thresholds

- **`MALICIOUS`**: Composite risk score `>= 50` or `>= 3` VirusTotal malicious engine detections.
- **`SUSPICIOUS`**: Composite risk score `15–49`, `1–2` VirusTotal malicious detections, or `>= 1` OTX pulse reference.
- **`CLEAN`**: Composite risk score `< 15` with zero malicious detections and zero OTX pulses.
- **`UNKNOWN`**: Indicator was not found in either dataset or API queries were skipped.

## Library Usage in Python

You can also import `threat_intel_aggregator` directly into other Python scripts or SOAR playbooks:

```python
from pathlib import Path
from threat_intel_aggregator import (
    AlienVaultOTXClient,
    ThreatCache,
    ThreatIntelAggregator,
    VirusTotalClient,
)

cache = ThreatCache(db_path=Path(".threat_intel_cache.sqlite"), ttl_seconds=3600)
vt_client = VirusTotalClient(api_key="YOUR_VT_KEY", cache=cache, rate_limit_per_min=4)
otx_client = AlienVaultOTXClient(api_key="YOUR_OTX_KEY", cache=cache)

aggregator = ThreatIntelAggregator(vt_client=vt_client, otx_client=otx_client)
report = aggregator.analyze_indicator("185.220.101[.]34")

print(f"Indicator: {report.indicator} ({report.ioc_type})")
print(f"Verdict:   {report.verdict} (Risk Score: {report.risk_score}/100)")
print(f"Malware:   {', '.join(report.malware_families)}")
```

## Security & Operational Notes

- **OPSEC & TLP Caution**: Per the [VirusTotal API Search Documentation](https://docs.virustotal.com/reference/api-search), any indicator submitted or queried may be shared with the broader security community. Avoid querying internal IPs, private URLs, or hashes of confidential documents.
- **Cache Hygiene**: The local cache file (`.threat_intel_cache.sqlite`) stores raw API JSON responses on disk. Add `*.sqlite` to your `.gitignore` so cached lookups are never committed to version control.

## License

Released under the MIT License.
