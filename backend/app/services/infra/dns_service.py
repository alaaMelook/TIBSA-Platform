"""
DNS / WHOIS / SSL / GeoIP Service – Stage 3 of the Infra Intelligence Pipeline.

Responsibilities:
  • DNS  – resolve A, AAAA, MX, NS, TXT, CNAME records via dnspython
  • WHOIS – query RDAP (rdap.org) for registrar / creation / expiry dates
  • SSL  – open TCP socket, perform TLS handshake, parse X.509 certificate
  • GeoIP – query ip-api.com (free, no key needed) for geographic context

All failures are surfaced as `error` fields; the pipeline never raises here.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import httpx

from app.schemas.infra_investigation import (
    DNSRecord,
    DNSResult,
    EnrichmentResults,
    GeoIPResult,
    SSLCertResult,
    WHOISResult,
)

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(12.0, connect=5.0)


class DNSService:
    """Resolves DNS records for a hostname using dnspython."""

    @staticmethod
    async def resolve(hostname: str) -> DNSResult:
        try:
            import dns.resolver  # dnspython must be installed (it is)
            import dns.exception

            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
            records: List[DNSRecord] = []

            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, rtype, lifetime=8.0)
                    ttl = answers.rrset.ttl if answers.rrset else None
                    for rdata in answers:
                        value = rdata.to_text().strip('"')
                        records.append(DNSRecord(type=rtype, value=value, ttl=ttl))
                except (dns.exception.DNSException, dns.resolver.NoAnswer,
                        dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass  # record type not found – normal

            return DNSResult(records=records)
        except Exception as exc:
            logger.warning("[DNS] Error for %s: %s", hostname, exc)
            return DNSResult(error=str(exc))


class WHOISService:
    """Queries RDAP for WHOIS-style registration metadata."""

    @staticmethod
    async def query(hostname: str) -> WHOISResult:
        # Determine the registered domain (eTLD+1) for RDAP
        parts = hostname.rstrip(".").split(".")
        if len(parts) < 2:
            return WHOISResult(error=f"Cannot extract registered domain from '{hostname}'.")
        registered = ".".join(parts[-2:])
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"https://rdap.org/domain/{registered}",
                    headers={"Accept": "application/rdap+json"},
                    follow_redirects=True,
                )
                resp.raise_for_status()
                data = resp.json()

            # Extract registrar from entities
            registrar: Optional[str] = None
            registrant_org: Optional[str] = None
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [None, []])[1]
                name = next(
                    (v[3] for v in vcard if isinstance(v, list) and v[0] == "fn"),
                    None,
                )
                if "registrar" in roles and name:
                    registrar = name
                if "registrant" in roles and name:
                    registrant_org = name

            # Parse dates from events
            creation_date: Optional[str] = None
            expiration_date: Optional[str] = None
            updated_date: Optional[str] = None
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date_str = event.get("eventDate", "")
                if action == "registration":
                    creation_date = date_str
                elif action == "expiration":
                    expiration_date = date_str
                elif action == "last changed":
                    updated_date = date_str

            # Compute domain age
            domain_age_days: Optional[int] = None
            is_newly_registered = False
            if creation_date:
                try:
                    created_dt = datetime.fromisoformat(
                        creation_date.replace("Z", "+00:00")
                    )
                    now = datetime.now(timezone.utc)
                    age = (now - created_dt).days
                    domain_age_days = max(0, age)
                    is_newly_registered = age < 90  # < 3 months = newly registered
                except ValueError:
                    pass

            # Collect status codes
            statuses = data.get("status", [])

            return WHOISResult(
                registrar=registrar,
                registrant_org=registrant_org,
                creation_date=creation_date,
                expiration_date=expiration_date,
                updated_date=updated_date,
                domain_age_days=domain_age_days,
                is_newly_registered=is_newly_registered,
                status=statuses,
            )
        except Exception as exc:
            logger.warning("[WHOIS/RDAP] Error for %s: %s", hostname, exc)
            return WHOISResult(error=str(exc))


class SSLService:
    """Fetches TLS certificate via raw socket handshake (no HTTP needed)."""

    @staticmethod
    async def fetch_cert(hostname: str, port: int = 443) -> SSLCertResult:
        try:
            # Run blocking SSL work in thread pool to stay non-blocking
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None, SSLService._fetch_blocking, hostname, port
            )
            return result
        except Exception as exc:
            logger.warning("[SSL] Error for %s:%d: %s", hostname, port, exc)
            return SSLCertResult(error=str(exc))

    @staticmethod
    def _fetch_blocking(hostname: str, port: int) -> SSLCertResult:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()  # dict form (DER-decoded)
                der_cert = ssock.getpeercert(binary_form=True)

        if not cert:
            return SSLCertResult(error="No certificate returned by server.")

        # --- Subject CN ---
        subject_cn: Optional[str] = None
        for field in cert.get("subject", []):
            for k, v in field:
                if k == "commonName":
                    subject_cn = v

        # --- Issuer ---
        issuer_cn: Optional[str] = None
        issuer_org: Optional[str] = None
        for field in cert.get("issuer", []):
            for k, v in field:
                if k == "commonName":
                    issuer_cn = v
                if k == "organizationName":
                    issuer_org = v

        # --- Serial number ---
        serial_number: Optional[str] = None
        if der_cert:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                x = x509.load_der_x509_certificate(der_cert, default_backend())
                serial_number = str(x.serial_number)
            except ImportError:
                pass  # cryptography not installed; skip serial

        # --- Validity dates ---
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        is_expired = False
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                is_expired = datetime.now(timezone.utc) > exp
            except ValueError:
                pass

        # --- Self-signed check ---
        is_self_signed = (issuer_cn is not None and issuer_cn == subject_cn)

        # --- SAN domains ---
        san_domains: List[str] = []
        for entry in cert.get("subjectAltName", []):
            if entry[0] == "DNS":
                san_domains.append(entry[1])

        return SSLCertResult(
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            issuer_org=issuer_org,
            serial_number=serial_number,
            not_before=not_before,
            not_after=not_after,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            san_domains=san_domains[:50],
        )


class GeoIPService:
    """Geolocates an IP address using ip-api.com (free, no key needed)."""

    @staticmethod
    async def lookup(ip: str) -> GeoIPResult:
        # Resolve hostname to IP first if it's not already an IP
        resolved_ip = ip
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            try:
                loop = asyncio.get_running_loop()
                resolved_ip = (await loop.run_in_executor(
                    None, socket.gethostbyname, ip
                ))
            except Exception:
                return GeoIPResult(ip=ip, error="Could not resolve hostname to IP.")

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{resolved_ip}",
                    params={
                        "fields": "status,message,country,countryCode,regionName,"
                                  "city,lat,lon,org,as,timezone,isp,query"
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            if data.get("status") != "success":
                return GeoIPResult(
                    ip=resolved_ip,
                    error=data.get("message", "ip-api.com returned non-success status."),
                )

            return GeoIPResult(
                ip=data.get("query", resolved_ip),
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("regionName"),
                city=data.get("city"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                org=data.get("isp"),
                asn=data.get("as"),
                timezone=data.get("timezone"),
            )
        except Exception as exc:
            logger.warning("[GeoIP] Error for %s: %s", resolved_ip, exc)
            return GeoIPResult(ip=resolved_ip, error=str(exc))


class EnrichmentService:
    """Runs DNS, WHOIS, SSL, and GeoIP lookups concurrently."""

    def __init__(self) -> None:
        self._dns = DNSService()
        self._whois = WHOISService()
        self._ssl = SSLService()
        self._geo = GeoIPService()

    async def run(
        self,
        hostname: str,
        target_type: str,
    ) -> EnrichmentResults:
        """
        Run DNS + WHOIS (for domains/URLs) and SSL + GeoIP concurrently.
        IP-only targets skip WHOIS; hash/email targets skip all.
        """
        if target_type in ("hash", "email"):
            return EnrichmentResults()

        tasks: dict = {}

        # DNS always for domain/url/ip
        tasks["dns"] = self._dns.resolve(hostname)

        # WHOIS only for domain and URL types
        if target_type in ("domain", "url"):
            tasks["whois"] = self._whois.query(hostname)

        # SSL – only if we have a hostname (not a raw IP)
        if target_type in ("domain", "url"):
            tasks["ssl"] = self._ssl.fetch_cert(hostname)

        # GeoIP – resolve hostname → IP always
        tasks["geoip"] = self._geo.lookup(hostname)

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        result_map = dict(zip(tasks.keys(), gathered))

        def _safe(key: str, default):
            val = result_map.get(key, default)
            return val if not isinstance(val, BaseException) else default

        return EnrichmentResults(
            dns=_safe("dns", DNSResult(error="Task failed.")),
            whois=_safe("whois", None),
            ssl=_safe("ssl", None),
            geoip=_safe("geoip", GeoIPResult(ip=hostname, error="Task failed.")),
        )
