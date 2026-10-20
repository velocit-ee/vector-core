"""
Velocitee Prism — High-Accuracy Multilingual PII Redaction Engine (PR-02, PR-03, PR-05)

Supports deterministic detection and ephemeral surrogate tokenization across
English, Estonian, Finnish, and Swedish enterprise text:
- EMAIL: RFC 5322 email addresses
- PHONE_INTL: International and Nordic/Baltic phone numbers (+372, +358, +46, +44, +1, etc.)
- CREDIT_CARD: 13-19 digit payment cards validated with Luhn Mod-10 checksum
- IBAN: European/international bank account numbers validated with ISO 7064 Mod-97-10
- NATIONAL_ID:
  - Estonian/Lithuanian 11-digit Isikukood validated with century/date + Mod-11 checksum
  - Finnish Henkilötunnus (HETU, DDMMYYCZZZQ) validated with Mod-31 control character
  - Swedish Personnummer (YYMMDD-XXXX / YYYYMMDD-XXXX) validated with Luhn Mod-10
- FINANCIAL_AMOUNT: Currency values anchored on $, €, £, EUR, USD, SEK, GBP, NOK, DKK
- IPV4_ADDRESS: Validated dotted-quad IPv4 addresses
- API_KEY_SECRET: Bearer tokens, sk-*, ghp_*, AKIA*, and high-entropy secret assignments
- PERSON_NAME: Unicode-aware titlecase personal names (including ÕÄÖÜŠŽÅ) using contextual
  triggers and vetted against a multilingual non-person phrase allowlist.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


# Default non-person capitalized phrases (greetings, cities, countries, corporate terms)
# that must NEVER be misclassified as PERSON_NAME (PR-05).
DEFAULT_PHRASE_ALLOWLIST: Set[str] = {
    "thank you",
    "thanks again",
    "many thanks",
    "best regards",
    "kind regards",
    "warm regards",
    "yours sincerely",
    "yours faithfully",
    "dear sir",
    "dear madam",
    "dear customer",
    "dear team",
    "hello world",
    "good morning",
    "good afternoon",
    "good evening",
    "new york",
    "los angeles",
    "san francisco",
    "united states",
    "united kingdom",
    "european union",
    "north america",
    "northern europe",
    "central bank",
    "tallinn estonia",
    "tartu estonia",
    "helsinki finland",
    "espoo finland",
    "tampere finland",
    "stockholm sweden",
    "gothenburg sweden",
    "malmö sweden",
    "oslo norway",
    "copenhagen denmark",
    "riga latvia",
    "vilnius lithuania",
    "telia company",
    "telia eesti",
    "telia finland",
    "telia sverige",
    "velocitee prism",
    "velocitee vector",
    "vector gateway",
    "sovereign hub",
    "hermes agent",
    "nous research",
    "customer support",
    "technical support",
    "service desk",
    "help desk",
    "account balance",
    "account number",
    "invoice number",
    "reference number",
    "purchase order",
    "annual report",
    "quarterly report",
    "executive summary",
    "project manager",
    "chief executive",
    "vice president",
    "general counsel",
    "human resources",
    "information technology",
    "data protection",
    "privacy policy",
    "service level",
    "high priority",
    "critical alert",
    "security operations",
    "network operations",
    "open source",
    "artificial intelligence",
    "machine learning",
    "large language",
    "cloud computing",
    "monday morning",
    "tuesday afternoon",
    "wednesday evening",
    "thursday morning",
    "friday afternoon",
    "january february",
    "march april",
    "first quarter",
    "second quarter",
    "third quarter",
    "fourth quarter",
}

# Individual capitalized words that cannot be part of a person's name
NON_NAME_WORDS: Set[str] = {
    "The", "This", "That", "These", "Those", "Please", "Thank", "Thanks",
    "Hello", "Hi", "Dear", "Best", "Kind", "Warm", "Regards", "Sincerely",
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    "January", "February", "March", "April", "June", "July", "August",
    "September", "October", "November", "December",
    "Invoice", "Account", "Customer", "Support", "Service", "System", "Network",
    "Server", "Router", "Gateway", "Firewall", "Database", "Report", "Summary",
    "Contract", "Agreement", "Payment", "Balance", "Transfer", "Amount", "Total",
    "Project", "Department", "Division", "Company", "Corporation", "Limited",
    "Estonia", "Finland", "Sweden", "Norway", "Denmark", "Latvia", "Lithuania",
    "Tallinn", "Tartu", "Narva", "Pärnu", "Helsinki", "Espoo", "Tampere",
    "Stockholm", "Gothenburg", "Malmö", "Uppsala", "London", "Paris", "Berlin",
    "Brussels", "New", "York", "San", "Francisco", "Los", "Angeles", "United",
    "European", "Union", "Sovereign", "Vector", "Velocitee", "Prism", "Telia",
    "Hermes", "Agent", "Claude", "Anthropic", "OpenAI", "Llama", "Mistral",
    "Status", "Action", "Review", "Urgent", "Priority", "Critical", "Security",
    "Section", "Article", "Clause", "Paragraph", "Table", "Figure", "Appendix",
    "Quarterly", "Annual", "Monthly", "Weekly", "Daily", "Current", "Previous",
    "Tere", "Lugupidamisega", "Parimate", "Soovidega", "Eesti", "Soome", "Rootsi",
    "Hei", "Kiitos", "Ystävällisin", "Terveisin", "Hej", "Tack", "Med", "Vänliga",
    "Hälsningar", "Kundtjänst", "Faktura", "Konto", "Betalning", "Rapport",
}


def verify_luhn(digits: str) -> bool:
    """Verifies a numeric string using the Luhn Mod-10 algorithm."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def verify_iban_mod97(raw_iban: str) -> bool:
    """Verifies an IBAN using ISO 7064 Mod-97-10."""
    cleaned = re.sub(r"[\s-]+", "", raw_iban).upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False
    if not cleaned[:2].isalpha() or not cleaned[2:4].isdigit():
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric_chars: List[str] = []
    for ch in rearranged:
        if ch.isdigit():
            numeric_chars.append(ch)
        elif "A" <= ch <= "Z":
            numeric_chars.append(str(ord(ch) - 55))
        else:
            return False
    return int("".join(numeric_chars)) % 97 == 1


def verify_estonian_isikukood(code: str) -> bool:
    """Verifies an 11-digit Estonian / Lithuanian personal identification code (Isikukood)."""
    if len(code) != 11 or not code.isdigit():
        return False
    if code[0] not in "123456":
        return False
    month = int(code[3:5])
    day = int(code[5:7])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    digits = [int(c) for c in code]
    w1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1]
    w2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]
    rem = sum(d * w for d, w in zip(digits[:10], w1)) % 11
    if rem == 10:
        rem = sum(d * w for d, w in zip(digits[:10], w2)) % 11
        if rem == 10:
            rem = 0
    return digits[10] == rem


_HETU_CHECK_CHARS = "0123456789ABCDEFHJKLMNPRSTUVWXY"


def verify_finnish_hetu(hetu: str) -> bool:
    """Verifies a Finnish personal identity code (Henkilötunnus, DDMMYYCZZZQ)."""
    if len(hetu) != 11:
        return False
    date_part = hetu[:6]
    sep = hetu[6]
    indiv = hetu[7:10]
    ctrl = hetu[10].upper()
    if not (date_part.isdigit() and indiv.isdigit() and sep in "+-ABCDEFUVWXY"):
        return False
    day = int(date_part[0:2])
    month = int(date_part[2:4])
    if not (1 <= day <= 31 and 1 <= month <= 12):
        return False
    num = int(date_part + indiv)
    return _HETU_CHECK_CHARS[num % 31] == ctrl


def verify_swedish_personnummer(raw: str) -> bool:
    """Verifies a Swedish personnummer (YYMMDD-XXXX or YYYYMMDD-XXXX) via Luhn Mod-10."""
    cleaned = re.sub(r"[\s+-]", "", raw)
    if len(cleaned) == 12 and cleaned[:2] in ("19", "20"):
        cleaned = cleaned[2:]
    if len(cleaned) != 10 or not cleaned.isdigit():
        return False
    month = int(cleaned[2:4])
    day = int(cleaned[4:6])
    if not (1 <= month <= 12 and 1 <= (day % 60) <= 31):
        return False
    # 10-digit Luhn check
    total = 0
    for idx, ch in enumerate(cleaned):
        n = int(ch)
        if idx % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@dataclass(frozen=True)
class RedactedEntityMetadata:
    """Public metadata about a redacted span — NEVER contains raw PII (PR-02)."""
    token: str
    entity_type: str
    length: int
    sha256_prefix: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "token": self.token,
            "type": self.entity_type,
            "length": self.length,
            "sha256_prefix": self.sha256_prefix,
        }


@dataclass
class EphemeralVault:
    """
    Request-scoped ephemeral surrogate vault (PR-02, PR-03).
    Lives exclusively on the call stack of a single HTTP request so that sanitized
    cloud LLM responses can be re-hydrated locally before the vault is destroyed.
    """
    _raw_to_token: Dict[Tuple[str, str], str] = field(default_factory=dict)
    _token_to_raw: Dict[str, str] = field(default_factory=dict)
    _type_counters: Dict[str, int] = field(default_factory=dict)
    _entities: List[RedactedEntityMetadata] = field(default_factory=list)

    def register(self, entity_type: str, raw_value: str) -> str:
        key = (entity_type, raw_value)
        if key in self._raw_to_token:
            return self._raw_to_token[key]

        count = self._type_counters.get(entity_type, 0) + 1
        self._type_counters[entity_type] = count
        token = f"[PII_{entity_type}_{count}]"
        self._raw_to_token[key] = token
        self._token_to_raw[token] = raw_value
        digest_prefix = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()[:8]
        self._entities.append(
            RedactedEntityMetadata(
                token=token,
                entity_type=entity_type,
                length=len(raw_value),
                sha256_prefix=digest_prefix,
            )
        )
        return token

    def rehydrate(self, text: str) -> str:
        """Replaces surrogate tokens with original values within the same request scope."""
        result = text
        for token, raw_val in self._token_to_raw.items():
            result = result.replace(token, raw_val)
        return result

    def clear(self) -> None:
        """Explicitly zeroes all in-memory mappings at the end of a request."""
        self._raw_to_token.clear()
        self._token_to_raw.clear()
        self._type_counters.clear()

    @property
    def public_entities(self) -> List[Dict[str, object]]:
        return [e.to_dict() for e in self._entities]

    @property
    def redaction_count(self) -> int:
        return len(self._entities)


# Compiled regex patterns
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b"
)

_IBAN_CANDIDATE_RE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]{4}){2,7}(?:[\s-]?[A-Z0-9]{1,4})?\b"
)

_CREDIT_CARD_CANDIDATE_RE = re.compile(
    r"\b(?:\d{4}[\s-]){3}\d{4}\b|\b\d{13,19}\b"
)

_FINNISH_HETU_RE = re.compile(
    r"\b\d{6}[+-ABCDEFUVWXY]\d{3}[0-9A-Z]\b",
    re.IGNORECASE,
)

_SWEDISH_PNR_RE = re.compile(
    r"\b(?:19|20)?\d{6}[+-]\d{4}\b"
)

_ESTONIAN_ID_RE = re.compile(
    r"\b[1-6]\d{10}\b"
)

# International & regional phone numbers:
# Requires either leading '+' with country code, or explicit phone context/Nordic prefix
_PHONE_INTL_RE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{2,4}[\s.-]?\d{2,4}(?:[\s.-]?\d{1,4})?|\(\d{3}\)\s*\d{3}[\s.-]\d{4})(?!\w)"
)

# Financial amounts: strictly requires currency symbol ($, €, £) or ISO currency code
_FINANCIAL_AMOUNT_RE = re.compile(
    r"(?:(?<![\w])(?:[$€£]|EUR|USD|SEK|GBP|NOK|DKK)[\s\u00a0]*\d{1,3}(?:[.,\s\u00a0]\d{3})*(?:[.,]\d{1,2})?(?:\s*(?:million|billion|k|M|B|miljonit|miljoonaa|miljoner))?\b|\b\d{1,3}(?:[.,\s\u00a0]\d{3})*(?:[.,]\d{1,2})?[\s\u00a0]*(?:€|EUR|USD|SEK|GBP|NOK|DKK)(?![\w]))"
)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_API_SECRET_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{20,})\b"
)

# Unicode upper/lower character classes for English, Estonian, Finnish, Swedish, German, French
_UPPER = r"A-ZÀ-ÖØ-ÞĀČĒĢĪĶĻŅŌŖŠŪŽÕÄÖÜ"
_LOWER = r"a-zß-öø-ÿāčēģīķļņōŗšūžõäöü"
_NAME_WORD = rf"[{_UPPER}][{_LOWER}]{{1,24}}(?:-[{_UPPER}][{_LOWER}]{{1,24}})?"

# Contextual name triggers (titles, labels, introductions in EN/ET/FI/SV)
_CONTEXT_NAME_RE = re.compile(
    rf"(?:\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Hr\.?|Pr\.?|Customer|Client|Patient|Employee|Contact|Name|Caller|User|Signed by|Prepared by|Reported by|Assigned to|Klient|Töötaja|Kontakt|Nimi|Asiakas|Potilas|Yhteyshenkilö|Kund|Anställd|Kontaktperson)\s*:?\s+)({_NAME_WORD}(?:\s+{_NAME_WORD}){{0,2}})"
)

# General two-part Unicode full name candidate
_TWO_WORD_NAME_RE = re.compile(
    rf"\b({_NAME_WORD}\s+{_NAME_WORD})\b"
)


class RedactionEngine:
    """
    Configurable, deterministic PII redaction engine supporting per-company profiles.
    """

    DEFAULT_ENABLED_ENTITIES: Tuple[str, ...] = (
        "API_KEY_SECRET",
        "EMAIL",
        "IBAN",
        "NATIONAL_ID",
        "CREDIT_CARD",
        "PHONE_INTL",
        "IPV4_ADDRESS",
        "FINANCIAL_AMOUNT",
        "PERSON_NAME",
    )

    def __init__(
        self,
        enabled_entities: Optional[Iterable[str]] = None,
        custom_patterns: Optional[Sequence[Dict[str, str]]] = None,
        allowlist: Optional[Iterable[str]] = None,
    ) -> None:
        self.enabled_entities: Set[str] = (
            set(enabled_entities)
            if enabled_entities is not None
            else set(self.DEFAULT_ENABLED_ENTITIES)
        )
        self.allowlist: Set[str] = set(DEFAULT_PHRASE_ALLOWLIST)
        if allowlist:
            for item in allowlist:
                self.allowlist.add(item.strip().lower())

        self.custom_compiled: List[Tuple[str, re.Pattern[str]]] = []
        if custom_patterns:
            for entry in custom_patterns:
                etype = str(entry.get("type", "CUSTOM")).upper()
                pat = str(entry.get("pattern", ""))
                if pat:
                    self.custom_compiled.append((etype, re.compile(pat)))

    def _is_allowlisted(self, candidate: str) -> bool:
        norm = " ".join(candidate.strip().split()).lower()
        return norm in self.allowlist

    def _is_valid_person_name(self, candidate: str, contextual: bool = False) -> bool:
        if self._is_allowlisted(candidate):
            return False
        words = candidate.split()
        if not words:
            return False
        for w in words:
            base_w = w.split("-")[0]
            if base_w in NON_NAME_WORDS or w in NON_NAME_WORDS:
                return False
            if len(w) < 2:
                return False
        if not contextual and len(words) < 2:
            return False
        return True

    def redact(
        self,
        text: str,
        vault: Optional[EphemeralVault] = None,
    ) -> Tuple[str, EphemeralVault]:
        """
        Redacts PII from `text` using a fresh or caller-supplied request-scoped `EphemeralVault`.
        Returns `(sanitized_text, vault)`.
        """
        active_vault = vault if vault is not None else EphemeralVault()
        if not text:
            return text, active_vault

        # Collect non-overlapping spans: List[(start, end, entity_type, raw_value)]
        spans: List[Tuple[int, int, str, str]] = []
        occupied = [False] * len(text)

        def try_add_span(start: int, end: int, etype: str, raw_val: str) -> None:
            if start < 0 or end <= start or end > len(text):
                return
            if self._is_allowlisted(raw_val):
                return
            if any(occupied[start:end]):
                return
            for i in range(start, end):
                occupied[i] = True
            spans.append((start, end, etype, raw_val))

        # 1. Custom company profile patterns (highest priority)
        for etype, cregex in self.custom_compiled:
            for m in cregex.finditer(text):
                try_add_span(m.start(), m.end(), etype, m.group(0))

        # 2. API keys & secrets
        if "API_KEY_SECRET" in self.enabled_entities:
            for m in _API_SECRET_RE.finditer(text):
                try_add_span(m.start(), m.end(), "API_KEY_SECRET", m.group(0))

        # 3. Email addresses
        if "EMAIL" in self.enabled_entities:
            for m in _EMAIL_RE.finditer(text):
                try_add_span(m.start(), m.end(), "EMAIL", m.group(0))

        # 4. IBAN (validated via ISO 7064 Mod-97)
        if "IBAN" in self.enabled_entities:
            for m in _IBAN_CANDIDATE_RE.finditer(text):
                candidate = m.group(0)
                if verify_iban_mod97(candidate):
                    try_add_span(m.start(), m.end(), "IBAN", candidate)

        # 5. National IDs (Finnish HETU, Swedish Personnummer, Estonian Isikukood)
        if "NATIONAL_ID" in self.enabled_entities:
            for m in _FINNISH_HETU_RE.finditer(text):
                candidate = m.group(0)
                if verify_finnish_hetu(candidate):
                    try_add_span(m.start(), m.end(), "NATIONAL_ID", candidate)

            for m in _SWEDISH_PNR_RE.finditer(text):
                candidate = m.group(0)
                if verify_swedish_personnummer(candidate):
                    try_add_span(m.start(), m.end(), "NATIONAL_ID", candidate)

            for m in _ESTONIAN_ID_RE.finditer(text):
                candidate = m.group(0)
                if verify_estonian_isikukood(candidate):
                    try_add_span(m.start(), m.end(), "NATIONAL_ID", candidate)

        # 6. Credit cards (validated via Luhn Mod-10)
        if "CREDIT_CARD" in self.enabled_entities:
            for m in _CREDIT_CARD_CANDIDATE_RE.finditer(text):
                candidate = m.group(0)
                digits = re.sub(r"[\s-]+", "", candidate)
                if verify_luhn(digits):
                    try_add_span(m.start(), m.end(), "CREDIT_CARD", candidate)

        # 7. International & regional phone numbers
        if "PHONE_INTL" in self.enabled_entities:
            for m in _PHONE_INTL_RE.finditer(text):
                candidate = m.group(0)
                digits = re.sub(r"\D", "", candidate)
                if 7 <= len(digits) <= 15:
                    try_add_span(m.start(), m.end(), "PHONE_INTL", candidate)

        # 8. IPv4 addresses
        if "IPV4_ADDRESS" in self.enabled_entities:
            for m in _IPV4_RE.finditer(text):
                try_add_span(m.start(), m.end(), "IPV4_ADDRESS", m.group(0))

        # 9. Financial amounts (currency-anchored)
        if "FINANCIAL_AMOUNT" in self.enabled_entities:
            for m in _FINANCIAL_AMOUNT_RE.finditer(text):
                try_add_span(m.start(), m.end(), "FINANCIAL_AMOUNT", m.group(0))

        # 10. Person names (contextual first, then vetted two-word Unicode names)
        if "PERSON_NAME" in self.enabled_entities:
            for m in _CONTEXT_NAME_RE.finditer(text):
                name_val = m.group(1)
                if self._is_valid_person_name(name_val, contextual=True):
                    try_add_span(m.start(1), m.end(1), "PERSON_NAME", name_val)

            for m in _TWO_WORD_NAME_RE.finditer(text):
                name_val = m.group(1)
                if self._is_valid_person_name(name_val, contextual=False):
                    try_add_span(m.start(1), m.end(1), "PERSON_NAME", name_val)

        # Sort spans in ascending order of start offset and assemble sanitized output
        spans.sort(key=lambda s: s[0])
        out_parts: List[str] = []
        cursor = 0
        for start, end, etype, raw_val in spans:
            out_parts.append(text[cursor:start])
            token = active_vault.register(etype, raw_val)
            out_parts.append(token)
            cursor = end
        out_parts.append(text[cursor:])

        return "".join(out_parts), active_vault
