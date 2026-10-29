from keysnare.masking import mask_secret

# Fake secrets are assembled at runtime so no complete token appears in the repository.
FAKE_AWS_KEY_ID = "AKIA" + "Q" * 12 + "WXYZ"


def test_long_secret_keeps_first_and_last_four_characters() -> None:
    assert mask_secret(FAKE_AWS_KEY_ID) == "AKIA****WXYZ"


def test_masked_output_never_contains_the_hidden_middle() -> None:
    secret = "abcd" + "SECRETMIDDLE" + "wxyz"

    assert "SECRETMIDDLE" not in mask_secret(secret)


def test_secret_of_exactly_sixteen_characters_shows_ends() -> None:
    assert mask_secret("1234" + "x" * 8 + "5678") == "1234****5678"


def test_short_secret_is_fully_hidden() -> None:
    assert mask_secret("p" * 15) == "****"


def test_empty_secret_is_fully_hidden() -> None:
    assert mask_secret("") == "****"


def test_mask_length_does_not_reveal_secret_length() -> None:
    assert len(mask_secret("a" * 20)) == len(mask_secret("a" * 200))
