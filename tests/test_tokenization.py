"""Tokenization consistency, uniqueness, and collision-avoidance tests."""

from privacyshield.tokenization import Tokenizer, TokenMapping
from privacyshield.detection import Detector, PERSON, EMAIL


def test_same_value_same_token_across_calls_and_columns():
    t = Tokenizer()
    a = t.tokenize_value(EMAIL, "ada@example.edu")
    b = t.tokenize_value(EMAIL, "ada@example.edu")
    assert a == b == "EMAIL_001"


def test_same_value_same_token_across_free_text_and_structured():
    det = Detector(use_ner=False)
    t = Tokenizer()
    # structured cell
    structured = t.tokenize_value(EMAIL, "ada@example.edu")
    # same value inside free text
    text = "Contact ada@example.edu for details."
    dets = det.detect_text(text)
    out = t.tokenize_spans(text, dets)
    assert structured in out
    assert out == f"Contact {structured} for details."


def test_different_values_get_different_tokens():
    t = Tokenizer()
    one = t.tokenize_value(EMAIL, "a@x.edu")
    two = t.tokenize_value(EMAIL, "b@x.edu")
    assert one != two
    assert {one, two} == {"EMAIL_001", "EMAIL_002"}


def test_different_entity_types_do_not_share_tokens():
    t = Tokenizer()
    person = t.tokenize_value(PERSON, "Sam")
    email = t.tokenize_value(EMAIL, "Sam")  # same text, different type
    assert person == "PERSON_001"
    assert email == "EMAIL_001"
    assert person != email


def test_token_does_not_collide_with_input_value():
    m = TokenMapping()
    # Pretend the dataset already literally contains "EMAIL_001".
    m.reserve(["EMAIL_001"])
    t = Tokenizer(m)
    token = t.tokenize_value(EMAIL, "someone@x.edu")
    assert token != "EMAIL_001"
    assert token == "EMAIL_002"


def test_empty_mapping_is_passed_through_not_discarded():
    # Regression: an empty TokenMapping is falsy; Tokenizer must keep it.
    m = TokenMapping()
    t = Tokenizer(m)
    t.tokenize_value(EMAIL, "x@y.edu")
    assert len(m) == 1
    assert m is t.mapping
