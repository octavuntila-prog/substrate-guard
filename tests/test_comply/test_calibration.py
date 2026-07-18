"""Semantic-encoder default + 0.85 threshold calibration (audit 2026-07-17 item 2.A step 3).

These run only with the sentence-transformers extra installed (.[comply-ml]);
they SKIP otherwise. They prove the two claims the L4 activation makes:
  1. the DEFAULT encoder is the real semantic one when the ML extra is present
     (so a certificate's `semantic` field is genuinely True, not vacuous);
  2. the 0.85 threshold actually separates paraphrases (>= 0.85, flagged as
     members) from unrelated text (< 0.85, non-members) -- i.e. the "semantic
     non-membership" guarantee is real under this encoder, not byte-exact only.
"""

from __future__ import annotations

import pytest

st = pytest.importorskip("sentence_transformers")  # noqa: F841  (skip marker)

from substrate_guard.comply.fingerprinter import (  # noqa: E402
    DeterministicFingerprinter,
    SemanticFingerprinter,
    default_fingerprinter,
    sentence_transformers_available,
)
from substrate_guard.comply.protocol import ThresholdNonMembershipProtocol  # noqa: E402

# CALIBRATION TRUTH (measured on all-MiniLM-L6-v2, 2026-07-18): at threshold 0.85
# the encoder flags NEAR-DUPLICATES / TIGHT paraphrases (~0.90-0.99) and leaves
# unrelated text far below (~0.0). LOOSE synonym-rewrite paraphrases score ~0.67-0.81
# -- BELOW 0.85 -- so 0.85 is a HIGH-PRECISION "near-duplicate" operating point, not
# an "any-paraphrase" detector. test_loose_paraphrase_falls_below_threshold pins that
# limitation honestly rather than overclaiming.
#
# (protected sentence, near-paraphrase that MUST match >= 0.85, unrelated that MUST NOT)
CASES = [
    (
        "The quarterly revenue report is confidential.",
        "The quarterly revenue report is confidential and private.",
        "The cat slept on the warm windowsill all afternoon.",
    ),
    (
        "How do I reset my password?",
        "How can I reset my password?",
        "Photosynthesis converts sunlight into chemical energy in plants.",
    ),
    (
        "Delete all user records from the production database.",
        "Delete all user records from the production database now.",
        "The weather today is sunny with a light breeze.",
    ),
]

# A genuinely LOOSE paraphrase (synonym-heavy rewrite): semantically the same intent,
# but MiniLM scores it ~0.80 -- below the 0.85 non-membership threshold.
LOOSE_PARAPHRASE = (
    "The quarterly revenue report is confidential and must not be shared.",
    "Do not share the confidential quarterly earnings document.",
)


@pytest.fixture(scope="module")
def encoder():
    return SemanticFingerprinter()


def test_default_encoder_is_semantic_when_available():
    assert sentence_transformers_available() is True
    assert isinstance(default_fingerprinter(), SemanticFingerprinter)


def test_certificate_semantic_flag_true_under_default():
    """With the ML extra, the DEFAULT protocol reports semantic=True (the field is
    no longer vacuous)."""
    p = ThresholdNonMembershipProtocol()  # default encoder = semantic here
    p.commit_training_data(["some protected corpus sentence"])
    cert = p.verify_non_membership("an unrelated query about weather")
    assert cert["semantic"] is True
    assert cert["encoder"].startswith("sbert:")


@pytest.mark.parametrize("protected,paraphrase,unrelated", CASES)
def test_paraphrase_similarity_above_threshold(encoder, protected, paraphrase, unrelated):
    emb_p = encoder.fingerprint(protected)
    sim_para = encoder.similarity(emb_p, encoder.fingerprint(paraphrase))
    sim_unrel = encoder.similarity(emb_p, encoder.fingerprint(unrelated))
    assert sim_para >= 0.85, f"paraphrase sim {sim_para:.3f} < 0.85"
    assert sim_unrel < 0.85, f"unrelated sim {sim_unrel:.3f} >= 0.85 (false match)"


@pytest.mark.parametrize("protected,paraphrase,unrelated", CASES)
def test_protocol_flags_paraphrase_but_clears_unrelated(protected, paraphrase, unrelated):
    """End-to-end: under the semantic encoder at threshold 0.85, a paraphrase of a
    protected doc is a MEMBER (verified=False), unrelated text is a NON-member."""
    p = ThresholdNonMembershipProtocol(threshold=0.85, fingerprinter=SemanticFingerprinter())
    p.commit_training_data([protected])
    assert p.verify_non_membership(paraphrase)["result"]["verified"] is False
    assert p.verify_non_membership(unrelated)["result"]["verified"] is True


def test_loose_paraphrase_falls_below_threshold(encoder):
    """HONEST limitation: a loose synonym-rewrite paraphrase scores BELOW 0.85, so
    0.85 is a near-duplicate operating point, not an any-paraphrase detector. Pinned
    so the calibration claim can't silently drift into an overclaim."""
    a, b = LOOSE_PARAPHRASE
    sim = encoder.similarity(encoder.fingerprint(a), encoder.fingerprint(b))
    assert 0.6 <= sim < 0.85, f"loose-paraphrase sim {sim:.3f} outside the documented gray band"


def test_deterministic_encoder_is_byte_exact_not_semantic():
    """Contrast: the deterministic fallback does NOT match even a NEAR paraphrase
    (proves the 'vacuous under deterministic' claim the certificate note makes)."""
    fp = DeterministicFingerprinter()
    protected, near_paraphrase, _ = CASES[0]
    sim = fp.similarity(fp.fingerprint(protected), fp.fingerprint(near_paraphrase))
    assert sim < 0.85, f"deterministic encoder unexpectedly matched a paraphrase (sim {sim:.3f})"
