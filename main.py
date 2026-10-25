#!/usr/bin/env python3
"""
Threat Intelligence Aggregator (VirusTotal v3 & AlienVault OTX v1)
==================================================================
A CLI tool and Python library that pulls live Indicators of Compromise (IoCs)
and enrichment telemetry from VirusTotal API v3 and AlienVault Open Threat
Exchange (OTX) DirectConnect API v1.

Key Features:
- Automatic IoC classification (IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256)
- Live threat feed ingestion from AlienVault OTX Subscribed Pulses
- Multi-source enrichment across VirusTotal v3 and AlienVault OTX v1
- Token-bucket rate limiting and exponential backoff for HTTP 429/5xx responses
- Local SQLite response caching to conserve API quotas
- Normalized risk scoring (0-100) and unified verdict classification
- Export to JSON, CSV, and formatted CLI tables

Usage Examples:
  # Enrich specific IoCs (reads VT_API_KEY and OTX_API_KEY from environment)
  python3 threat_intel_aggregator.py -i 8.8.8.8 evil-domain.com 44d88612fea8a8f36de82e1278abb02f

  # Pull latest live IoCs from subscribed AlienVault OTX pulses and cross-check top hits on VT
  python3 threat_intel_aggregator.py --pull-pulses --pulse-limit 5 --output-json report.json

  # Enrich from a file of indicators and export to CSV
  python3 threat_intel_aggregator.py -f indicators.txt --output-csv enriched_iocs.csv

  # Run offline demonstration with realistic simulated API responses
  python3 threat_intel_aggregator.py --demo
"""

from __future__ import annotations

import argparse
import base64
import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("threat_intel_aggregator")


# ---------------------------------------------------------------------------
# Constants & API Endpoints
# ---------------------------------------------------------------------------
VT_BASE_URL = "https://www.virustotal.com/api/v3"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

REGEX_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
REGEX_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
REGEX_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
REGEX_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
@dataclass
class VTEnrichment:
  """Normalized telemetry returned from VirusTotal API v3."""

  queried: bool = False
  found: bool = False
  malicious: int = 0
  suspicious: int = 0
  harmless: int = 0
  undetected: int = 0
  total_engines: int = 0
  reputation: int = 0
  country: Optional[str] = None
  as_owner: Optional[str] = None
  asn: Optional[int] = None
  categories: List[str] = field(default_factory=list)
  tags: List[str] = field(default_factory=list)
  last_analysis_date: Optional[str] = None
  permalink: Optional[str] = None
  error: Optional[str] = None


@dataclass
class OTXEnrichment:
  """Normalized telemetry returned from AlienVault OTX API v1."""

  queried: bool = False
  found: bool = False
  pulse_count: int = 0
  pulse_names: List[str] = field(default_factory=list)
  malware_families: List[str] = field(default_factory=list)
  adversaries: List[str] = field(default_factory=list)
  tags: List[str] = field(default_factory=list)
  country: Optional[str] = None
  asn: Optional[str] = None
  reputation: int = 0
  permalink: Optional[str] = None
  error: Optional[str] = None


@dataclass
class AggregatedIoCReport:
  """Unified threat intelligence record combining VirusTotal and AlienVault OTX."""

  indicator: str
  ioc_type: str
  risk_score: int  # 0 to 100
  verdict: str  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN
  country: str
  asn_owner: str
  vt_detections: str
  otx_pulses: int
  tags: List[str]
  malware_families: List[str]
  timestamp_utc: str
  virustotal: VTEnrichment
  alienvault_otx: OTXEnrichment

  def to_flat_dict(self) -> Dict[str, Any]:
    """Flatten record for CSV export."""
    return {
        "indicator": self.indicator,
        "ioc_type": self.ioc_type,
        "verdict": self.verdict,
        "risk_score": self.risk_score,
        "vt_detections": self.vt_detections,
        "vt_malicious": self.virustotal.malicious,
        "vt_suspicious": self.virustotal.suspicious,
        "vt_reputation": self.virustotal.reputation,
        "otx_pulse_count": self.otx_pulses,
        "country": self.country,
        "asn_owner": self.asn_owner,
        "malware_families": "; ".join(self.malware_families),
        "tags": "; ".join(self.tags),
        "vt_permalink": self.virustotal.permalink or "",
        "otx_permalink": self.alienvault_otx.permalink or "",
        "timestamp_utc": self.timestamp_utc,
    }


# ---------------------------------------------------------------------------
# IoC Classification Utility
# ---------------------------------------------------------------------------
def classify_ioc(raw_indicator: str) -> Tuple[str, str]:
  """Normalize and classify an Indicator of Compromise.

  Returns:
      Tuple of (normalized_indicator, ioc_type) where ioc_type is one of:
      'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', or 'unknown'.
  """
  indicator = raw_indicator.strip()
  # Defang common patterns (e.g., hxxps://, [.], (:))
  indicator = (
      indicator.replace("hxxp://", "http://")
      .replace("hxxps://", "https://")
      .replace("[.]", ".")
      .replace("(.)", ".")
      .replace("[:]", ":")
  )

  # Check IP addresses
  try:
    ip_obj = ipaddress.ip_address(indicator)
    return str(ip_obj), ("ipv4" if ip_obj.version == 4 else "ipv6")
  except ValueError:
    pass

  # Check Hashes
  if REGEX_MD5.match(indicator):
    return indicator.lower(), "md5"
  if REGEX_SHA1.match(indicator):
    return indicator.lower(), "sha1"
  if REGEX_SHA256.match(indicator):
    return indicator.lower(), "sha256"

  # Check URLs
  parsed = urllib.parse.urlparse(indicator)
  if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
    return indicator, "url"

  # Check Domains
  if REGEX_DOMAIN.match(indicator):
    return indicator.lower(), "domain"

  return indicator, "unknown"


# ---------------------------------------------------------------------------
# Local SQLite Response Cache
# ---------------------------------------------------------------------------
class ThreatCache:
  """Lightweight SQLite cache to avoid redundant API hits within TTL."""

  def __init__(
      self,
      db_path: Path = Path(".threat_intel_cache.sqlite"),
      ttl_seconds: int = 3600,
  ):
    self.db_path = db_path
    self.ttl_seconds = ttl_seconds
    self._init_db()

  def _init_db(self) -> None:
    if self.ttl_seconds <= 0:
      return
    with sqlite3.connect(self.db_path) as conn:
      conn.execute("""
                CREATE TABLE IF NOT EXISTS api_cache (
                    cache_key TEXT PRIMARY KEY,
                    response_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """)

  def get(
      self, source: str, ioc_type: str, indicator: str
  ) -> Optional[Dict[str, Any]]:
    if self.ttl_seconds <= 0:
      return None
    key = f"{source}:{ioc_type}:{indicator}"
    now = int(time.time())
    with sqlite3.connect(self.db_path) as conn:
      row = conn.execute(
          "SELECT response_json, created_at FROM api_cache WHERE cache_key"
          " = ?",
          (key,),
      ).fetchone()
      if row and (now - row[1]) < self.ttl_seconds:
        return json.loads(row[0])
    return None

  def set(
      self, source: str, ioc_type: str, indicator: str, payload: Dict[str, Any]
  ) -> None:
    if self.ttl_seconds <= 0:
      return
    key = f"{source}:{ioc_type}:{indicator}"
    now = int(time.time())
    with sqlite3.connect(self.db_path) as conn:
      conn.execute(
          """
                INSERT OR REPLACE INTO api_cache (cache_key, response_json, created_at)
                VALUES (?, ?, ?)
                """,
          (key, json.dumps(payload), now),
      )


# ---------------------------------------------------------------------------
# HTTP Client with Rate Limiting & Exponential Backoff
# ---------------------------------------------------------------------------
class RateLimitedHttpClient:
  """Zero-dependency HTTP client enforcing minimum request intervals and retries."""

  def __init__(
      self, min_interval_sec: float = 0.0, timeout: int = 20, max_retries: int = 3
  ):
    self.min_interval_sec = min_interval_sec
    self.timeout = timeout
    self.max_retries = max_retries
    self._last_call_ts = 0.0

  def get_json(
      self, url: str, headers: Dict[str, str]
  ) -> Tuple[int, Optional[Dict[str, Any]], Optional[str]]:
    """Perform GET request and return (status_code, parsed_json, error_message)."""
    for attempt in range(1, self.max_retries + 1):
      elapsed = time.time() - self._last_call_ts
      if self.min_interval_sec > 0 and elapsed < self.min_interval_sec:
        sleep_for = self.min_interval_sec - elapsed
        logger.debug("Rate limiter sleeping %.2fs before %s", sleep_for, url)
        time.sleep(sleep_for)

      req = urllib.request.Request(url, headers=headers, method="GET")
      self._last_call_ts = time.time()

      try:
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
          raw = resp.read().decode("utf-8", errors="replace")
          return resp.status, json.loads(raw), None
      except urllib.error.HTTPError as exc:
        if exc.code == 404:
          return 404, None, "Not found in dataset"
        if exc.code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
          backoff = 2**attempt
          logger.warning(
              "HTTP %d from %s (attempt %d/%d). Backing off %ds...",
              exc.code,
              url,
              attempt,
              self.max_retries,
              backoff,
          )
          time.sleep(backoff)
          continue
        err_body = ""
        try:
          err_body = exc.read().decode("utf-8", errors="replace")[:200]
        except Exception:
          pass
        return exc.code, None, f"HTTP {exc.code}: {err_body or exc.reason}"
      except urllib.error.URLError as exc:
        if attempt < self.max_retries:
          time.sleep(2**attempt)
          continue
        return 0, None, f"Network error: {exc.reason}"
      except Exception as exc:
        return 0, None, f"Unexpected error: {exc}"

    return 0, None, "Exhausted retries"


# ---------------------------------------------------------------------------
# VirusTotal API v3 Client
# ---------------------------------------------------------------------------
class VirusTotalClient:
  """Client for VirusTotal v3 REST API."""

  def __init__(
      self,
      api_key: Optional[str],
      cache: ThreatCache,
      rate_limit_per_min: int = 4,
  ):
    self.api_key = api_key
    self.cache = cache
    interval = 60.0 / rate_limit_per_min if rate_limit_per_min > 0 else 0.0
    self.http = RateLimitedHttpClient(min_interval_sec=interval)

  @staticmethod
  def _url_id(url: str) -> str:
    """Generate VirusTotal v3 URL identifier (unpadded base64url)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")

  def _endpoint_for(
      self, indicator: str, ioc_type: str
  ) -> Tuple[Optional[str], Optional[str]]:
    if ioc_type in ("ipv4", "ipv6"):
      return (
          f"{VT_BASE_URL}/ip_addresses/{indicator}",
          f"https://www.virustotal.com/gui/ip-address/{indicator}",
      )
    if ioc_type == "domain":
      return (
          f"{VT_BASE_URL}/domains/{indicator}",
          f"https://www.virustotal.com/gui/domain/{indicator}",
      )
    if ioc_type in ("md5", "sha1", "sha256"):
      return (
          f"{VT_BASE_URL}/files/{indicator}",
          f"https://www.virustotal.com/gui/file/{indicator}",
      )
    if ioc_type == "url":
      uid = self._url_id(indicator)
      return (
          f"{VT_BASE_URL}/urls/{uid}",
          f"https://www.virustotal.com/gui/url/{uid}",
      )
    return None, None

  def lookup(self, indicator: str, ioc_type: str) -> VTEnrichment:
    if not self.api_key:
      return VTEnrichment(queried=False, error="VT_API_KEY not configured")

    endpoint, gui_link = self._endpoint_for(indicator, ioc_type)
    if not endpoint:
      return VTEnrichment(
          queried=False, error=f"Unsupported IoC type for VT: {ioc_type}"
      )

    cached = self.cache.get("vt", ioc_type, indicator)
    if cached is not None:
      return self._parse_response(cached, gui_link)

    headers = {"Accept": "application/json", "x-apikey": self.api_key}
    status, data, err = self.http.get_json(endpoint, headers=headers)
    if status == 404:
      return VTEnrichment(queried=True, found=False, permalink=gui_link)
    if err or not data:
      return VTEnrichment(queried=True, found=False, error=err)

    self.cache.set("vt", ioc_type, indicator, data)
    return self._parse_response(data, gui_link)

  @staticmethod
  def _parse_response(
      payload: Dict[str, Any], gui_link: Optional[str]
  ) -> VTEnrichment:
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    categories_dict = attrs.get("categories", {})
    categories = (
         sorted(set(categories_dict.values()))
        if isinstance(categories_dict, dict)
        else []
    )

    last_ts = attrs.get("last_analysis_date")
    last_date_str = (
        datetime.fromtimestamp(last_ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        if isinstance(last_ts, (int, float))
        else None
    )

    return VTEnrichment(
        queried=True,
        found=True,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        total_engines=total,
        reputation=int(attrs.get("reputation", 0)),
        country=attrs.get("country"),
        as_owner=attrs.get("as_owner"),
        asn=attrs.get("asn"),
        categories=categories,
        tags=list(attrs.get("tags", [])),
        last_analysis_date=last_date_str,
        permalink=gui_link,
    )


# ---------------------------------------------------------------------------
# AlienVault OTX DirectConnect API v1 Client
# ---------------------------------------------------------------------------
class AlienVaultOTXClient:
  """Client for AlienVault Open Threat Exchange (OTX) API v1."""

  OTX_TYPE_MAP = {
      "ipv4": "IPv4",
      "ipv6": "IPv6",
      "domain": "domain",
      "url": "url",
      "md5": "file",
      "sha1": "file",
      "sha256": "file",
  }

  OTX_PULSE_IOC_MAP = {
      "IPv4": "ipv4",
      "IPv6": "ipv6",
      "domain": "domain",
      "hostname": "domain",
      "URL": "url",
      "FileHash-MD5": "md5",
      "FileHash-SHA1": "sha1",
      "FileHash-SHA256": "sha256",
  }

  def __init__(self, api_key: Optional[str], cache: ThreatCache):
    self.api_key = api_key
    self.cache = cache
    self.http = RateLimitedHttpClient(min_interval_sec=0.25)

  def lookup(self, indicator: str, ioc_type: str) -> OTXEnrichment:
    if not self.api_key:
      return OTXEnrichment(queried=False, error="OTX_API_KEY not configured")

    otx_type = self.OTX_TYPE_MAP.get(ioc_type)
    if not otx_type:
      return OTXEnrichment(
          queried=False, error=f"Unsupported IoC type for OTX: {ioc_type}"
      )

    gui_link = f"https://otx.alienvault.com/indicator/{otx_type}/{urllib.parse.quote(indicator, safe='')}"
    cached = self.cache.get("otx", ioc_type, indicator)
    if cached is not None:
      return self._parse_response(cached, gui_link)

    encoded_ioc = urllib.parse.quote(indicator, safe="")
    endpoint = f"{OTX_BASE_URL}/indicators/{otx_type}/{encoded_ioc}/general"
    headers = {"Accept": "application/json", "X-OTX-API-KEY": self.api_key}

    status, data, err = self.http.get_json(endpoint, headers=headers)
    if status == 404:
      return OTXEnrichment(queried=True, found=False, permalink=gui_link)
    if err or not data:
      return OTXEnrichment(queried=True, found=False, error=err)

    self.cache.set("otx", ioc_type, indicator, data)
    return self._parse_response(data, gui_link)

  def pull_subscribed_pulses(
      self, limit: int = 5, max_iocs: int = 25
  ) -> List[str]:
    """Fetch recent live IoCs from subscribed AlienVault OTX threat pulses."""
    if not self.api_key:
      raise RuntimeError("OTX_API_KEY is required to pull subscribed pulses.")

    endpoint = f"{OTX_BASE_URL}/pulses/subscribed?limit={limit}"
    headers = {"Accept": "application/json", "X-OTX-API-KEY": self.api_key}
    status, data, err = self.http.get_json(endpoint, headers=headers)
    if err or not data:
      raise RuntimeError(
          f"Failed to fetch OTX pulses (HTTP {status}): {err}"
      )

    extracted: List[str] = []
    seen = set()
    for pulse in data.get("results", []):
      pulse_name = pulse.get("name", "Unnamed Pulse")
      logger.info("Ingesting OTX Pulse: %s", pulse_name)
      for ind in pulse.get("indicators", []):
        ind_type = ind.get("type")
        ind_val = ind.get("indicator", "").strip()
        if ind_type in self.OTX_PULSE_IOC_MAP and ind_val and ind_val not in seen:
          seen.add(ind_val)
          extracted.append(ind_val)
          if len(extracted) >= max_iocs:
            return extracted
    return extracted

  @staticmethod
  def _parse_response(
      payload: Dict[str, Any], gui_link: Optional[str]
  ) -> OTXEnrichment:
    pulse_info = payload.get("pulse_info", {})
    pulse_count = int(pulse_info.get("count", 0))
    pulses = pulse_info.get("pulses", [])

    pulse_names: List[str] = []
    malware_families: set[str] = set()
    adversaries: set[str] = set()
    tags: set[str] = set()

    for pulse in pulses:
      if pulse.get("name"):
        pulse_names.append(pulse["name"])
      for mf in pulse.get("malware_families", []):
        if isinstance(mf, dict) and mf.get("display_name"):
          malware_families.add(mf["display_name"])
        elif isinstance(mf, str) and mf:
          malware_families.add(mf)
      if pulse.get("adversary"):
        adversaries.add(pulse["adversary"])
      for tag in pulse.get("tags", []):
        if tag:
          tags.add(str(tag))

    return OTXEnrichment(
        queried=True,
        found=True,
        pulse_count=pulse_count,
        pulse_names=pulse_names[:10],
        malware_families=sorted(malware_families),
        adversaries=sorted(adversaries),
        tags=sorted(tags)[:15],
        country=payload.get("country_code") or payload.get("country_name"),
        asn=payload.get("asn"),
        reputation=int(payload.get("reputation") or 0),
        permalink=gui_link,
    )


# ---------------------------------------------------------------------------
# Scoring & Aggregation Engine
# ---------------------------------------------------------------------------
class ThreatIntelAggregator:
  """Combines VirusTotal and AlienVault OTX telemetry into unified risk reports."""

  def __init__(
      self,
      vt_client: VirusTotalClient,
      otx_client: AlienVaultOTXClient,
  ):
    self.vt_client = vt_client
    self.otx_client = otx_client

  @staticmethod
  def compute_risk_and_verdict(
      vt: VTEnrichment, otx: OTXEnrichment
  ) -> Tuple[int, str]:
    """Calculate a normalized 0-100 risk score and categorical verdict."""
    if not vt.found and not otx.found:
      return 0, "UNKNOWN"

    score = 0.0

    # VirusTotal weight (up to 70 points)
    if vt.found:
      if vt.malicious >= 10:
        score += 70.0
      elif vt.malicious >= 3:
        score += 50.0 + (vt.malicious - 3) * 2.8
      elif vt.malicious >= 1:
        score += 25.0 + (vt.malicious - 1) * 12.0
      elif vt.suspicious >= 2:
        score += 15.0
      elif vt.suspicious == 1:
        score += 8.0

      if vt.reputation < -10:
        score += min(15.0, abs(vt.reputation) * 0.2)

    # AlienVault OTX weight (up to 45 points)
    if otx.found:
      if otx.pulse_count >= 10:
        score += 35.0
      elif otx.pulse_count >= 3:
        score += 22.0
      elif otx.pulse_count >= 1:
        score += 12.0

      if otx.malware_families or otx.adversaries:
        score += 10.0

    final_score = max(0, min(100, int(round(score))))

    if final_score >= 50 or vt.malicious >= 3:
      verdict = "MALICIOUS"
    elif final_score >= 15 or vt.malicious >= 1 or otx.pulse_count >= 1:
      verdict = "SUSPICIOUS"
    else:
      verdict = "CLEAN"

    return final_score, verdict

  def analyze_indicator(self, raw_indicator: str) -> AggregatedIoCReport:
    indicator, ioc_type = classify_ioc(raw_indicator)
    logger.info("Analyzing %s (%s)...", indicator, ioc_type)

    vt_res = self.vt_client.lookup(indicator, ioc_type)
    otx_res = self.otx_client.lookup(indicator, ioc_type)

    risk_score, verdict = self.compute_risk_and_verdict(vt_res, otx_res)

    country = vt_res.country or otx_res.country or "N/A"
    asn_owner = (
        f"AS{vt_res.asn} ({vt_res.as_owner})"
        if vt_res.asn and vt_res.as_owner
        else (vt_res.as_owner or otx_res.asn or "N/A")
    )
    vt_detections = (
        f"{vt_res.malicious}/{vt_res.total_engines}"
        if vt_res.found and vt_res.total_engines > 0
        else ("Not Found" if vt_res.queried and not vt_res.error else "Skipped")
    )

    combined_tags = sorted(
        set(vt_res.tags + vt_res.categories + otx_res.tags)
    )[:12]

    return AggregatedIoCReport(
        indicator=indicator,
        ioc_type=ioc_type,
        risk_score=risk_score,
        verdict=verdict,
        country=country,
        asn_owner=asn_owner,
        vt_detections=vt_detections,
        otx_pulses=otx_res.pulse_count if otx_res.found else 0,
        tags=combined_tags,
        malware_families=otx_res.malware_families,
        timestamp_utc=datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        virustotal=vt_res,
        alienvault_otx=otx_res,
    )


# ---------------------------------------------------------------------------
# Simulated Demo Dataset (for testing without live API keys)
# ---------------------------------------------------------------------------
def build_demo_reports() -> List[AggregatedIoCReport]:
  """Generate realistic multi-source threat intelligence reports for --demo mode."""
  now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
  samples = [
      (
          "185.220.101.34",
          "ipv4",
          VTEnrichment(
              queried=True,
              found=True,
              malicious=14,
              suspicious=2,
              harmless=52,
              undetected=26,
              total_engines=94,
              reputation=-42,
              country="DE",
              as_owner="Zwiebelfreunde e.V.",
              asn=205100,
              categories=["tor-exit-node", "scanner"],
              tags=["tor", "suspicious-udp"],
              last_analysis_date="2026-10-25 14:20:00 UTC",
              permalink="https://www.virustotal.com/gui/ip-address/185.220.101.34",
          ),
          OTXEnrichment(
              queried=True,
              found=True,
              pulse_count=19,
              pulse_names=[
                  "Active C2 & Tor Exit Nodes Q4",
                  "Brute-Force SSH Scanners",
              ],
              malware_families=["Mirai", "CobaltStrike"],
              adversaries=["APT29"],
              tags=["c2", "tor", "ssh-bruteforce"],
              country="DE",
              asn="AS205100 Zwiebelfreunde e.V.",
              reputation=-3,
              permalink="https://otx.alienvault.com/indicator/IPv4/185.220.101.34",
          ),
      ),
      (
          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
          "sha256",
          VTEnrichment(
              queried=True,
              found=True,
              malicious=66,
              suspicious=0,
              harmless=0,
              undetected=6,
              total_engines=72,
              reputation=-91,
              tags=["peexe", "signed", "eicar"],
              last_analysis_date="2026-10-25 15:05:12 UTC",
              permalink="https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
          ),
          OTXEnrichment(
              queried=True,
              found=True,
              pulse_count=8,
              pulse_names=["Known Malware Test & Loader Hashes"],
              malware_families=["LockBit", "RedLine Stealer"],
              tags=["ransomware", "stealer", "payload"],
              permalink="https://otx.alienvault.com/indicator/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
          ),
      ),
      (
          "login-micros0ft-security-update.com",
          "domain",
          VTEnrichment(
              queried=True,
              found=True,
              malicious=9,
              suspicious=3,
              harmless=61,
              undetected=19,
              total_engines=92,
              reputation=-28,
              categories=["phishing", "newly-registered-domain"],
              tags=["phishing", "credential-harvesting"],
              last_analysis_date="2026-10-25 12:40:00 UTC",
              permalink="https://www.virustotal.com/gui/domain/login-micros0ft-security-update.com",
          ),
          OTXEnrichment(
              queried=True,
              found=True,
              pulse_count=4,
              pulse_names=["M365 Credential Phishing Infrastructure"],
              malware_families=["EvilProxy"],
              tags=["aitm", "phishing", "m365"],
              permalink="https://otx.alienvault.com/indicator/domain/login-micros0ft-security-update.com",
          ),
      ),
      (
          "8.8.8.8",
          "ipv4",
          VTEnrichment(
              queried=True,
              found=True,
              malicious=0,
              suspicious=0,
              harmless=85,
              undetected=9,
              total_engines=94,
              reputation=540,
              country="US",
              as_owner="GOOGLE",
              asn=15169,
              categories=["dns-resolver"],
              tags=["benign", "google-dns"],
              last_analysis_date="2026-10-25 15:30:00 UTC",
              permalink="https://www.virustotal.com/gui/ip-address/8.8.8.8",
          ),
          OTXEnrichment(
              queried=True,
              found=True,
              pulse_count=0,
              country="US",
              asn="AS15169 GOOGLE",
              permalink="https://otx.alienvault.com/indicator/IPv4/8.8.8.8",
          ),
      ),
  ]

  reports: List[AggregatedIoCReport] = []
  for ind, ioc_type, vt, otx in samples:
    score, verdict = ThreatIntelAggregator.compute_risk_and_verdict(vt, otx)
    asn_owner = (
        f"AS{vt.asn} ({vt.as_owner})"
        if vt.asn and vt.as_owner
        else (vt.as_owner or otx.asn or "N/A")
    )
    reports.append(
        AggregatedIoCReport(
            indicator=ind,
            ioc_type=ioc_type,
            risk_score=score,
            verdict=verdict,
            country=vt.country or otx.country or "N/A",
            asn_owner=asn_owner,
            vt_detections=f"{vt.malicious}/{vt.total_engines}",
            otx_pulses=otx.pulse_count,
            tags=sorted(set(vt.tags + vt.categories + otx.tags))[:10],
            malware_families=otx.malware_families,
            timestamp_utc=now_iso,
            virustotal=vt,
            alienvault_otx=otx,
        )
    )
  return reports


# ---------------------------------------------------------------------------
# Output Formatting & Exports
# ---------------------------------------------------------------------------
def print_summary_table(reports: List[AggregatedIoCReport]) -> None:
  """Render a clean ASCII/Unicode summary table to stdout."""
  if not reports:
    print("No indicators analyzed.")
    return

  header = (
      f"{'INDICATOR':<38} | {'TYPE':<7} | {'VERDICT':<10} | {'RISK':>4} | "
      f"{'VT HITS':>8} | {'OTX PULSES':>10} | {'COUNTRY':<7} | {'FAMILIES / TAGS'}"
  )
  sep = "-" * len(header)
  print("\n" + sep)
  print(header)
  print(sep)

  for r in sorted(reports, key=lambda x: x.risk_score, reverse=True):
    ind_disp = (
        r.indicator if len(r.indicator) <= 38 else r.indicator[:35] + "..."
    )
    context_items = r.malware_families + r.tags
    context_str = ", ".join(context_items[:4]) if context_items else "-"
    print(
        f"{ind_disp:<38} | {r.ioc_type:<7} | {r.verdict:<10} | "
        f"{r.risk_score:>4} | {r.vt_detections:>8} | {r.otx_pulses:>10} | "
        f"{r.country:<7} | {context_str}"
    )
  print(sep + "\n")


def export_json(reports: List[AggregatedIoCReport], output_path: Path) -> None:
  payload = {
      "generated_at_utc": datetime.now(timezone.utc).strftime(
          "%Y-%m-%dT%H:%M:%SZ"
      ),
      "total_indicators": len(reports),
      "malicious_count": sum(1 for r in reports if r.verdict == "MALICIOUS"),
      "suspicious_count": sum(1 for r in reports if r.verdict == "SUSPICIOUS"),
      "results": [asdict(r) for r in reports],
  }
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
  logger.info("Saved JSON threat intelligence report to %s", output_path)


def export_csv(reports: List[AggregatedIoCReport], output_path: Path) -> None:
  if not reports:
    return
  rows = [r.to_flat_dict() for r in reports]
  output_path.parent.mkdir(parents=True, exist_ok=True)
  with output_path.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
  logger.info("Saved CSV threat intelligence report to %s", output_path)


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      description=(
          "Threat Intelligence Aggregator: Pulls and correlates live IoCs "
          "from VirusTotal API v3 and AlienVault OTX API v1."
      )
  )
  parser.add_argument(
      "-i",
      "--indicators",
      nargs="+",
      help="One or more IoCs (IPs, domains, URLs, MD5/SHA1/SHA256 hashes).",
  )
  parser.add_argument(
      "-f",
      "--input-file",
      type=Path,
      help="Path to a text file containing one IoC per line (# comments ignored).",
  )
  parser.add_argument(
      "--pull-pulses",
      action="store_true",
      help="Pull live IoCs from your subscribed AlienVault OTX pulses.",
  )
  parser.add_argument(
      "--pulse-limit",
      type=int,
      default=5,
      help="Number of recent subscribed OTX pulses to fetch (default: 5).",
  )
  parser.add_argument(
      "--max-pulse-iocs",
      type=int,
      default=20,
      help="Maximum IoCs to extract when pulling live OTX pulses (default: 20).",
  )
  parser.add_argument(
      "--vt-api-key",
      default=os.environ.get("VT_API_KEY"),
      help="VirusTotal API v3 key (defaults to VT_API_KEY env variable).",
  )
  parser.add_argument(
      "--otx-api-key",
      default=os.environ.get("OTX_API_KEY"),
      help="AlienVault OTX API v1 key (defaults to OTX_API_KEY env variable).",
  )
  parser.add_argument(
      "--vt-rate-limit",
      type=int,
      default=4,
      help="VirusTotal requests per minute limit (default: 4 for public API; set 0 for unlimited).",
  )
  parser.add_argument(
      "--cache-ttl",
      type=int,
      default=3600,
      help="Local SQLite cache TTL in seconds (default: 3600; set 0 to disable).",
  )
  parser.add_argument(
      "--output-json",
      type=Path,
      help="Export full normalized telemetry to a JSON file.",
  )
  parser.add_argument(
      "--output-csv",
      type=Path,
      help="Export flattened summary metrics to a CSV file.",
  )
  parser.add_argument(
      "--demo",
      action="store_true",
      help="Run with realistic simulated VirusTotal & AlienVault OTX responses.",
  )
  return parser.parse_args(argv)


def load_indicators_from_file(filepath: Path) -> List[str]:
  if not filepath.exists():
    raise FileNotFoundError(f"Input file not found: {filepath}")
  indicators: List[str] = []
  for line in filepath.read_text(encoding="utf-8").splitlines():
    cleaned = line.strip()
    if cleaned and not cleaned.startswith("#"):
      indicators.append(cleaned)
  return indicators


def main(argv: Optional[List[str]] = None) -> int:
  args = parse_args(argv)

  if args.demo:
    logger.info(
        "Running in DEMO mode with simulated VirusTotal v3 & AlienVault OTX v1 telemetry..."
    )
    reports = build_demo_reports()
    print_summary_table(reports)
    if args.output_json:
      export_json(reports, args.output_json)
    if args.output_csv:
      export_csv(reports, args.output_csv)
    return 0

  target_iocs: List[str] = []
  if args.indicators:
    target_iocs.extend(args.indicators)
  if args.input_file:
    target_iocs.extend(load_indicators_from_file(args.input_file))

  cache = ThreatCache(ttl_seconds=args.cache_ttl)
  vt_client = VirusTotalClient(
      api_key=args.vt_api_key,
      cache=cache,
      rate_limit_per_min=args.vt_rate_limit,
  )
  otx_client = AlienVaultOTXClient(api_key=args.otx_api_key, cache=cache)

  if args.pull_pulses:
    try:
      live_iocs = otx_client.pull_subscribed_pulses(
          limit=args.pulse_limit, max_iocs=args.max_pulse_iocs
      )
      logger.info(
          "Pulled %d live IoCs from subscribed OTX pulses.", len(live_iocs)
      )
      target_iocs.extend(live_iocs)
    except Exception as exc:
      logger.error("%s", exc)
      return 1

  # Deduplicate while preserving order
  deduped_iocs = list(dict.fromkeys(target_iocs))
  if not deduped_iocs:
    logger.error(
        "No indicators provided. Pass -i <IOC>, -f <FILE>, --pull-pulses, or --demo."
    )
    return 1

  if not args.vt_api_key and not args.otx_api_key:
    logger.warning(
        "Neither VT_API_KEY nor OTX_API_KEY is set. Set environment variables "
        "or run with --demo to preview output."
    )

  aggregator = ThreatIntelAggregator(vt_client=vt_client, otx_client=otx_client)
  reports = [aggregator.analyze_indicator(ioc) for ioc in deduped_iocs]

  print_summary_table(reports)

  if args.output_json:
    export_json(reports, args.output_json)
  if args.output_csv:
    export_csv(reports, args.output_csv)

  return 0


if __name__ == "__main__":
  sys.exit(main())
