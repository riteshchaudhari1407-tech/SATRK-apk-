"""
Rule Engine Service
--------------------
A deterministic, explainable scam-pattern detector for India's
"digital arrest" and authority-impersonation fraud. This is the
backbone of the risk score: every category is backed by real regex
signatures, and scoring uses diminishing-returns-per-hit plus a
"combination bonus" — because real scam scripts stack multiple
tactics (impersonation + isolation + financial ask) while
unrelated text rarely triggers more than one category at all.

This exact scoring model is mirrored on the frontend as an offline
fallback, so behaviour stays consistent whether or not the backend
is reachable during a demo.
"""

import re
from dataclasses import dataclass, field
from typing import List, Pattern

from app.utils.helpers import extract_excerpt


@dataclass
class ThreatCategoryDef:
    name: str
    max_score: float
    first_hit_fraction: float
    description: str
    patterns: List[Pattern]


@dataclass
class CategoryHit:
    category: str
    weight: int
    excerpt: str
    description: str


@dataclass
class RuleEngineResult:
    score: float
    hits: List[CategoryHit] = field(default_factory=list)
    combo_bonus: float = 0
    linguistic_bonus: float = 0
    distinct_categories: int = 0


def _p(pattern: str) -> Pattern:
    return re.compile(pattern, re.IGNORECASE)


THREAT_CATEGORIES: List[ThreatCategoryDef] = [
    ThreatCategoryDef(
        name="Authority Impersonation",
        max_score=28,
        first_hit_fraction=0.78,
        description=(
            "Message invokes a police, investigative or regulatory identity. "
            "Real Indian agencies (CBI, RBI, Police, ED, Cyber Cell) never open "
            "a criminal case over WhatsApp, SMS or a phone call."
        ),
        patterns=[
            _p(r"\bcbi\b"),
            _p(r"central bureau of investigation"),
            _p(r"\brbi\b"),
            _p(r"reserve bank of india"),
            _p(r"income tax department"),
            _p(r"cyber\s?cell"),
            _p(r"cyber\s?crime"),
            _p(r"\btrai\b"),
            _p(r"narcotics?( control)? bureau"),
            _p(r"\bncb\b"),
            _p(r"enforcement directorate"),
            _p(r"\bed officer\b"),
            _p(r"customs department"),
            _p(r"supreme court"),
            _p(r"high court"),
            _p(r"\bmagistrate\b"),
            _p(r"\bfir\b"),
            _p(r"arrest warrant"),
            _p(r"non[-\s]?bailable warrant"),
            _p(r"police station"),
            _p(r"sub[-\s]?inspector"),
            _p(r"\bdcp\b"),
            _p(r"warrant"),



            _p(r"case file"),
        ],
    ),
    ThreatCategoryDef(
        name="Digital Arrest / Isolation Tactics",
        max_score=32,
        first_hit_fraction=0.80,
        description=(
            "This is the signature pattern of India's 'digital arrest' scam — "
            "victims are told to stay on a video call and cut off from everyone "
            "while impersonators simulate a virtual custody."
        ),
        patterns=[
            _p(r"digital arrest"),
            _p(r"stay on (this|the) (call|video)"),
            _p(r"do not disconnect"),
            _p(r"do not hang\s?up"),
            _p(r"video call immediately"),
            _p(r"stay on video"),
            _p(r"virtual custody"),
            _p(r"house arrest"),
            _p(r"do not leave the frame"),
            _p(r"keep (your )?camera on"),
            _p(r"under surveillance"),
            _p(r"do not tell anyone"),
            _p(r"do not inform (your )?family"),
            _p(r"keep this (confidential|secret)"),
            _p(r"top secret investigation"),
            _p(r"video call pe raho"),
            _p(r"kisi ko mat batana"),
            _p(r"giraftar"),
            _p(r"cannot contact anyone"),
            _p(r"डिजिटल अरेस्ट"),
            _p(r"वारंट"),
            _p(r"गिरफ्तारी"),
            _p(r"अटक वॉरंट"),



            _p(r"गुन्हा दाखल"),
        ],
    ),
    ThreatCategoryDef(
        name="Urgency & Threat Pressure",
        max_score=16,
        first_hit_fraction=0.50,
        description=(
            "Manufactured urgency and legal threats are used to short-circuit "
            "rational thinking so the victim complies before verifying "
            "anything independently."
        ),
        patterns=[
            _p(r"immediate action"),
            _p(r"act (immediately|now)"),
            _p(r"right now"),
            _p(r"within \d+ ?(minutes|hours|mins)"),
            _p(r"last warning"),
            _p(r"final notice"),
            _p(r"failure to comply"),
            _p(r"legal action will be taken"),
            _p(r"you will be arrested"),
            _p(r"non[-\s]?compliance"),
            _p(r"\burgent\b"),
            _p(r"case (has been |)dala gaya"),
            _p(r"police action will be taken"),
            _p(r"join this video call"),
        ],
    ),
    ThreatCategoryDef(
        name="Financial & Identity Fraud Bait",
        max_score=20,
        first_hit_fraction=0.65,
        description=(
            'Requests for OTP, UPI details or "transfer to a safe account" are '
            "the actual mechanism scammers use to move money — no legitimate "
            "authority ever asks for this."
        ),
        patterns=[
            _p(r"share (your )?otp"),
            _p(r"upi pin"),
            _p(r"account (will be |has been )?frozen"),
            _p(r"pay a fine"),
            _p(r"refundable (security )?deposit"),
            _p(r"processing fee"),
            _p(r"transfer (the )?(amount|money|funds)"),
            _p(r"safe account"),
            _p(r"verification fee"),
            _p(r"kyc update"),
            _p(r"verify (your )?kyc"),
            _p(r"link(ed)? (your )?aadhaar"),
            _p(r"aadhaar (number|card|has been).{0,25}(linked|blocked|misuse)"),
            _p(r"pan card.{0,25}(linked|blocked|misuse)"),
            _p(r"parcel contains"),
            _p(r"illegal parcel"),
            _p(r"drugs (found|detected) in your name"),
            _p(r"paisa transfer karo"),
            _p(r"money laundering"),
        ],
    ),
    ThreatCategoryDef(
        name="Phishing & Remote-Access Bait",
        max_score=14,
        first_hit_fraction=0.55,
        description=(
            'Links, "install this app" or remote-access requests '
            "(AnyDesk/TeamViewer) are used to steal credentials or hand over "
            "full control of the device."
        ),
        patterns=[
            _p(r"click here"),
            _p(r"click (the|this) link"),
            _p(r"install anydesk"),
            _p(r"install teamviewer"),
            _p(r"download this app"),
            _p(r"remote access"),
            _p(r"bit\.ly/"),
            _p(r"tinyurl\.com/"),
            _p(r"verify your identity by clicking"),
        ],
    ),
]


class RuleEngineService:
    """Deterministic, explainable scam-signature scorer."""

    def __init__(self, categories: List[ThreatCategoryDef] = None):
        self.categories = categories or THREAT_CATEGORIES

    def analyze(self, raw_text: str) -> RuleEngineResult:
        text = (raw_text or "").strip()

        hits: List[CategoryHit] = []
        total = 0.0

        for category in self.categories:
            matches = [
                m for m in (p.search(text) for p in category.patterns) if m
            ]

            if not matches:






                continue

            # First match already carries most of the category's weight
            # (one clear phrase is real evidence); further matches close
            # the gap to the category max with diminishing returns.
            category_score = category.max_score * (
                1 - (1 - category.first_hit_fraction) ** len(matches)
            )

            total += category_score

            hits.append(
                CategoryHit(
                    category=category.name,
                    weight=round(category_score),
                    excerpt=extract_excerpt(text, matches[0]),
                    description=category.description,
                )
            )

        distinct_categories = len(hits)

        if distinct_categories >= 4:
            combo_bonus = 30
        elif distinct_categories == 3:
            combo_bonus = 30
        elif distinct_categories == 2:
            combo_bonus = 22
        else:
            combo_bonus = 0

        total += combo_bonus

        linguistic_bonus = 0.0

        if hits:
            exclamations = len(re.findall(r"!", text))
            upper_words = len(re.findall(r"\b[A-Z]{4,}\b", text))

            linguistic_bonus = min(8.0, exclamations * 1.5 + upper_words * 2)
            total += linguistic_bonus

        score = max(0.0, min(100.0, total))

        return RuleEngineResult(
            score=score,
            hits=sorted(hits, key=lambda h: h.weight, reverse=True),
            combo_bonus=combo_bonus,
            linguistic_bonus=linguistic_bonus,
            distinct_categories=distinct_categories,








        )