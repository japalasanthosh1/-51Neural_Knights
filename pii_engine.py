"""
PII Detection Engine — 3-Layer ML Pipeline
Layer 1: Regex patterns (SSN, Aadhaar, credit card, phone, email, etc.)
Layer 2: spaCy NER (PERSON, ORG, GPE, LOC, DATE)
Layer 3: Transformer NER - dslim/bert-base-NER (PER, ORG, LOC, MISC)
"""
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PIIMatch:
    pii_type: str
    value: str
    masked_value: str
    confidence: float
    severity: str
    context: str = ""
    detection_method: str = ""  # regex | spacy | transformer
    start: int = 0
    end: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Layer 1: Regex Patterns
# ═══════════════════════════════════════════════════════════════════════════════

REGEX_PATTERNS = {
    "SSN": {
        "pattern": r'\b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b',
        "severity": "CRITICAL",
        "confidence": 0.90,
        "validate": lambda m: (
            100 <= int(m.replace("-", "").replace(" ", "")[:3]) <= 899
            and int(m.replace("-", "").replace(" ", "")[:3]) != 666
        ),
    },
    "AADHAAR": {
        "pattern": r'\b([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})\b',
        "severity": "CRITICAL",
        "confidence": 0.85,
        "validate": lambda m: len(m.replace("-", "").replace(" ", "")) == 12,
    },
    "CREDIT_CARD": {
        "pattern": r'\b((?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4})\b',
        "severity": "CRITICAL",
        "confidence": 0.88,
        "validate": lambda m: _luhn_check(m.replace("-", "").replace(" ", "")),
    },
    "EMAIL": {
        "pattern": r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b',
        "severity": "HIGH",
        "confidence": 0.95,
        "validate": None,
    },
    "PHONE_IN": {
        "pattern": r'(?:\+91[\s-]?)?(?:\b[6-9]\d{4}[\s-]?\d{5}\b)',
        "severity": "HIGH",
        "confidence": 0.80,
        "validate": lambda m: len(re.sub(r'[\s\-+]', '', m)) >= 10,
    },
    "PHONE_US": {
        "pattern": r'(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
        "severity": "HIGH",
        "confidence": 0.78,
        "validate": lambda m: len(re.sub(r'[\s\-().+]', '', m)) >= 10,
    },
    "PAN_CARD": {
        "pattern": r'\b([A-Z]{5}\d{4}[A-Z])\b',
        "severity": "HIGH",
        "confidence": 0.88,
        "validate": None,
    },
    "PASSPORT": {
        "pattern": r'\b([A-Z][0-9]{7,8})\b',
        "severity": "HIGH",
        "confidence": 0.70,
        "validate": None,
    },
    "IP_ADDRESS": {
        "pattern": r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
        "severity": "MEDIUM",
        "confidence": 0.75,
        "validate": lambda m: all(0 <= int(p) <= 255 for p in m.split(".")),
    },
    "DOB": {
        "pattern": r'\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b',
        "severity": "MEDIUM",
        "confidence": 0.65,
        "validate": None,
    },
    "API_KEY": {
        "pattern": r'(?:api[_\-]?key|secret|token|password)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        "severity": "CRITICAL",
        "confidence": 0.82,
        "validate": None,
    },
    "LINKEDIN_PROFILE": {
        "pattern": r'https?:\/\/(?:www\.)?linkedin\.com\/in\/([a-zA-Z0-9_\-]+)\/?',
        "severity": "MEDIUM",
        "confidence": 0.90,
        "validate": None,
    },
    "GITHUB_PROFILE": {
        "pattern": r'https?:\/\/(?:www\.)?github\.com\/([a-zA-Z0-9_\-]+)\/?',
        "severity": "MEDIUM",
        "confidence": 0.90,
        "validate": None,
    },
    "TWITTER_PROFILE": {
        "pattern": r'https?:\/\/(?:www\.)?(?:twitter\.com|x\.com)\/([a-zA-Z0-9_\-]+)\/?',
        "severity": "MEDIUM",
        "confidence": 0.90,
        "validate": None,
    },
    "SOCIAL_HANDLE": {
        "pattern": r'\B@([a-zA-Z0-9_]{3,20})\b',
        "severity": "MEDIUM",
        "confidence": 0.65,
        "validate": None,
    },
    "SOCIAL_NAME": {
        "pattern": r'\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\s*\|\s*(?:LinkedIn|GitHub|Twitter|X|Facebook|Instagram)\b',
        "severity": "HIGH",
        "confidence": 0.85,
        "validate": None,
    },
}


def _luhn_check(num: str) -> bool:
    try:
        digits = [int(d) for d in num]
        odd = digits[-1::-2]
        even = digits[-2::-2]
        total = sum(odd) + sum(d * 2 - 9 if d * 2 > 9 else d * 2 for d in even)
        return total % 10 == 0
    except (ValueError, IndexError):
        return False


def _mask_value(value: str, pii_type: str) -> str:
    if len(value) <= 4:
        return "****"
    if pii_type == "EMAIL":
        parts = value.split("@")
        return parts[0][:2] + "***@" + parts[1] if len(parts) == 2 else "***"
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


def _get_context(text: str, start: int, end: int, window: int = 40) -> str:
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    ctx = text[ctx_start:ctx_end].replace("\n", " ").strip()
    if ctx_start > 0:
        ctx = "..." + ctx
    if ctx_end < len(text):
        ctx = ctx + "..."
    return ctx


# ═══════════════════════════════════════════════════════════════════════════════
# Main Engine
# ═══════════════════════════════════════════════════════════════════════════════

class PIIEngine:
    """3-layer PII detection: Regex + spaCy NER + Transformer NER."""

    def __init__(self):
        self.nlp = None      # spaCy model
        self.ner_pipe = None  # Transformer NER pipeline
        self._load_models()

    def _load_models(self):
        """Load ML models (spaCy + Transformer)."""
        # Layer 2: spaCy
        try:
            import spacy
            self.nlp = spacy.load("en_core_web_sm")
            logger.info("✓ spaCy en_core_web_sm loaded")
        except Exception as e:
            logger.warning(f"spaCy not available: {e}")
            self.nlp = None

        # Layer 3: Transformers
        try:
            from transformers import pipeline
            self.ner_pipe = pipeline(
                "ner",
                model="dslim/bert-base-NER",
                aggregation_strategy="simple",
                device=-1,  # CPU
            )
            logger.info("✓ BERT NER model loaded")
        except Exception as e:
            logger.warning(f"Transformer NER not available: {e}")
            self.ner_pipe = None

    def detect(self, text: str, max_length: int = 50000) -> List[PIIMatch]:
        """Run all 3 detection layers and merge results, deduplicated by value."""
        if not text:
            return []

        text = text[:max_length]
        all_matches: List[PIIMatch] = []

        # Layer 1: Regex
        all_matches.extend(self._detect_regex(text))

        # Layer 2: spaCy NER
        all_matches.extend(self._detect_spacy(text))

        # Layer 3: Transformer NER
        all_matches.extend(self._detect_transformer(text))

        # Deduplicate by (normalized_value, pii_type) — keep highest confidence
        unique = {}
        for m in all_matches:
            key = (m.value.strip().lower(), m.pii_type)
            if key not in unique or m.confidence > unique[key].confidence:
                unique[key] = m

        result = sorted(unique.values(), key=lambda m: m.start)
        return result

    def _detect_regex(self, text: str) -> List[PIIMatch]:
        """Layer 1: Regex-based pattern detection."""
        matches = []
        for pii_type, config in REGEX_PATTERNS.items():
            for match in re.finditer(config["pattern"], text, re.IGNORECASE):
                value = match.group(1) if match.lastindex else match.group(0)
                if config["validate"]:
                    try:
                        if not config["validate"](value):
                            continue
                    except Exception:
                        continue
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=value,
                    masked_value=_mask_value(value, pii_type),
                    confidence=config["confidence"],
                    severity=config["severity"],
                    context=_get_context(text, match.start(), match.end()),
                    detection_method="regex",
                    start=match.start(),
                    end=match.end(),
                ))
        return matches

    def _detect_spacy(self, text: str) -> List[PIIMatch]:
        """Layer 2: spaCy NER detection."""
        if not self.nlp:
            return []

        matches = []
        # Process in chunks to handle large text
        chunk_size = 100000
        for offset in range(0, len(text), chunk_size):
            chunk = text[offset:offset + chunk_size]
            try:
                doc = self.nlp(chunk[:self.nlp.max_length])
            except Exception:
                continue

            for ent in doc.ents:
                if ent.label_ not in ("PERSON", "ORG", "GPE", "LOC", "DATE", "NORP"):
                    continue

                # Map spaCy labels to PII types
                pii_type = {
                    "PERSON": "PERSON_NAME",
                    "ORG": "ORGANIZATION",
                    "GPE": "LOCATION",
                    "LOC": "LOCATION",
                    "DATE": "DATE_ENTITY",
                    "NORP": "NATIONALITY",
                }.get(ent.label_, ent.label_)

                severity = "HIGH" if pii_type in ("PERSON_NAME",) else "MEDIUM"
                confidence = 0.75 if ent.label_ in ("PERSON", "ORG") else 0.65

                # Skip very short or numeric-only entities
                if len(ent.text.strip()) < 2 or ent.text.strip().isdigit():
                    continue

                abs_start = offset + ent.start_char
                abs_end = offset + ent.end_char

                matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=ent.text,
                    masked_value=_mask_value(ent.text, pii_type),
                    confidence=confidence,
                    severity=severity,
                    context=_get_context(text, abs_start, abs_end),
                    detection_method="spacy",
                    start=abs_start,
                    end=abs_end,
                ))
        return matches

    def _detect_transformer(self, text: str) -> List[PIIMatch]:
        """Layer 3: Transformer (BERT) NER detection."""
        if not self.ner_pipe:
            return []

        matches = []
        # BERT has token limit, process in chunks
        chunk_size = 400
        words = text.split()

        for i in range(0, len(words), chunk_size):
            chunk = " ".join(words[i:i + chunk_size])
            try:
                entities = self.ner_pipe(chunk)
            except Exception:
                continue

            for ent in entities:
                if ent.get("score", 0) < 0.7:
                    continue

                label = ent.get("entity_group", "")
                word = ent.get("word", "").strip()

                if len(word) < 2:
                    continue

                pii_type = {
                    "PER": "PERSON_NAME",
                    "ORG": "ORGANIZATION",
                    "LOC": "LOCATION",
                    "MISC": "MISC_ENTITY",
                }.get(label, label)

                severity = "HIGH" if pii_type == "PERSON_NAME" else "MEDIUM"

                # Find position in original text
                try:
                    start_pos = text.find(word)
                    end_pos = start_pos + len(word) if start_pos >= 0 else 0
                except Exception:
                    start_pos, end_pos = 0, 0

                matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=word,
                    masked_value=_mask_value(word, pii_type),
                    confidence=round(ent.get("score", 0.8), 2),
                    severity=severity,
                    context=_get_context(text, start_pos, end_pos) if start_pos >= 0 else "",
                    detection_method="transformer",
                    start=start_pos,
                    end=end_pos,
                ))
        return matches

    def get_model_status(self) -> Dict:
        """Return status of loaded models."""
        return {
            "regex": True,
            "spacy": self.nlp is not None,
            "transformer": self.ner_pipe is not None,
            "spacy_model": "en_core_web_sm" if self.nlp else None,
            "transformer_model": "dslim/bert-base-NER" if self.ner_pipe else None,
        }
