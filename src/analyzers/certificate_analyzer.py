"""Certificate hygiene checks against /api/trust/cert/search."""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class CertFinding:
    severity: str
    rule_id: str
    rule_description: str
    issue: str
    reason: str
    solution: str
    rule_details: dict
    interface: str = ""
    opnsense_path: str = "System > Trust > Certificates"
    implementation_steps: list[str] = field(default_factory=list)


# Match OpenSSL-style RFC 5280 dates ("Jan  2 12:34:56 2027 GMT")
_NOTAFTER_FORMATS = (
    "%b %d %H:%M:%S %Y %Z",
    "%b  %d %H:%M:%S %Y %Z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S%z",
)


def _parse_notafter(raw: str) -> datetime | None:
    if not raw:
        return None
    s = raw.strip()
    for fmt in _NOTAFTER_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return None


def _decode_cert_blob(blob: str) -> dict:
    """Best-effort parse of a base64 PEM blob from /api/trust/cert/search rows."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except Exception:
        return {}

    if not blob:
        return {}
    try:
        raw = base64.b64decode(blob, validate=False)
        cert = x509.load_pem_x509_certificate(raw, default_backend())
    except Exception as e:
        logger.debug(f"cert parse failed: {e}")
        return {}

    try:
        key_size = cert.public_key().key_size
    except Exception:
        key_size = 0
    try:
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    except Exception:
        sig_alg = ""
    return {
        "not_after": cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=UTC),
        "key_size": key_size,
        "sig_alg": sig_alg.lower(),
        "subject": cert.subject.rfc4514_string(),
    }


class CertificateAnalyzer:
    """Flag certs that expire soon, use weak keys, or use SHA1."""

    def __init__(self, exceptions: list[dict] | None = None) -> None:
        self.exceptions = exceptions or []

    def analyze(self, certs: list[dict]) -> list[CertFinding]:
        findings: list[CertFinding] = []
        if not certs:
            return findings

        now = datetime.now(UTC)

        for cert in certs:
            uuid = cert.get("uuid", "")
            descr = cert.get("descr") or cert.get("name") or uuid or "cert"

            # Field names per OPNsense trust controller; fall back to PEM parse.
            not_after_raw = cert.get("not_after") or cert.get("valid_to") or cert.get("end_date")
            key_size = 0
            try:
                key_size = int(cert.get("keysize") or cert.get("key_size") or 0)
            except (ValueError, TypeError):
                key_size = 0
            sig_alg = (cert.get("sig_alg") or cert.get("signature_algorithm") or "").lower()

            parsed_dt = _parse_notafter(not_after_raw)
            if parsed_dt is None or not key_size or not sig_alg:
                meta = _decode_cert_blob(cert.get("crt") or cert.get("certificate") or "")
                if meta:
                    parsed_dt = parsed_dt or meta.get("not_after")
                    key_size = key_size or meta.get("key_size", 0)
                    sig_alg = sig_alg or meta.get("sig_alg", "")

            # Expired or near expiry.
            if parsed_dt:
                delta_days = (parsed_dt - now).days
                if delta_days < 0:
                    findings.append(CertFinding(
                        severity="HIGH",
                        rule_id=uuid or descr,
                        rule_description=descr,
                        issue=f"Zertifikat abgelaufen ({-delta_days} Tage)",
                        reason="Abgelaufene Zertifikate fuehren zu Browser-Warnungen und brechen DoT/HTTPS-Funktionen.",
                        solution="Zertifikat erneuern oder ersetzen.",
                        rule_details={"not_after": str(parsed_dt), "days": delta_days},
                        implementation_steps=[
                            "1. System > Trust > Certificates oeffnen.",
                            "2. Eintrag bearbeiten und neu signieren oder importieren.",
                            "3. Speichern und Apply.",
                        ],
                    ))
                elif delta_days < 30:
                    findings.append(CertFinding(
                        severity="MEDIUM",
                        rule_id=uuid or descr,
                        rule_description=descr,
                        issue=f"Zertifikat laeuft in {delta_days} Tagen ab",
                        reason="Bei kurzer Restlaufzeit drohen Ausfaelle vor allem bei automatisierten Diensten.",
                        solution="Erneuerung jetzt einplanen.",
                        rule_details={"not_after": str(parsed_dt), "days": delta_days},
                    ))

            # Weak RSA key.
            if key_size and key_size < 2048:
                findings.append(CertFinding(
                    severity="HIGH",
                    rule_id=(uuid or descr) + "_keysize",
                    rule_description=descr,
                    issue=f"Schwache Schluessellaenge ({key_size} bit)",
                    reason="Schluessel unter 2048 bit gelten als unsicher (NIST SP 800-131A).",
                    solution="Mit mindestens 2048 bit RSA oder ECDSA P-256 neu erzeugen.",
                    rule_details={"key_size": key_size},
                ))

            # SHA1 signature.
            if "sha1" in sig_alg or "md5" in sig_alg:
                findings.append(CertFinding(
                    severity="HIGH",
                    rule_id=(uuid or descr) + "_sigalg",
                    rule_description=descr,
                    issue=f"Schwacher Signatur-Algorithmus ({sig_alg})",
                    reason="SHA1/MD5 sind kryptographisch gebrochen, Browser akzeptieren das nicht mehr.",
                    solution="Zertifikat mit SHA-256 oder besser neu signieren.",
                    rule_details={"sig_alg": sig_alg},
                ))

        return findings
