"""Hide secrets before they are shown or stored anywhere."""

MASK = "****"
VISIBLE_CHARS = 4
# Below this length, showing 8 characters would reveal most of the secret.
MIN_LENGTH_TO_SHOW_ENDS = 16


def mask_secret(secret: str) -> str:
    """Return the secret with everything except its first and last 4 characters hidden."""
    if len(secret) < MIN_LENGTH_TO_SHOW_ENDS:
        return MASK
    return secret[:VISIBLE_CHARS] + MASK + secret[-VISIBLE_CHARS:]
