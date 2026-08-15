"""Homoglyph / confusable-character normalization.

The goal is to collapse a domain label onto the "skeleton" a human eye reads,
so that ``paypa1``, ``pаypal`` (Cyrillic a) and ``paypaI`` all fold down to the
same string ``paypal`` and can be compared against a brand token.

Two layers:

1. A multi-character ASCII lookalike table (``rn`` -> ``m``, ``vv`` -> ``w``)
   which must be applied greedily before the single-character map.
2. A single-character map that folds Unicode confusables (Cyrillic, Greek,
   fullwidth, digits) and ASCII digit-for-letter swaps down to a base letter.

Order of operations elsewhere: punycode-decode -> NFKC -> ``skeleton()``.
"""

import unicodedata

# Multi-character sequences that look like a single letter. Applied first,
# longest-first, so "rn" collapses to "m" before the single-char pass runs.
MULTI_CHAR = {
    "rn": "m",
    "vv": "w",
}

# Single-character confusables -> canonical ASCII letter.
# Includes ASCII digit substitutions plus a curated set of Unicode homoglyphs
# from the Cyrillic and Greek blocks and common fullwidth/typographic forms.
SINGLE_CHAR = {
    # ASCII digit-for-letter
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "$": "s",
    "@": "a",
    "!": "i",
    "|": "l",
    # Cyrillic lookalikes
    "а": "a",  # U+0430
    "е": "e",  # U+0435
    "о": "o",  # U+043E
    "р": "p",  # U+0440
    "с": "c",  # U+0441
    "х": "x",  # U+0445
    "у": "y",  # U+0443
    "ѕ": "s",  # U+0455
    "і": "i",  # U+0456
    "ј": "j",  # U+0458
    "ԁ": "d",  # U+0501
    "һ": "h",  # U+04BB
    "ӏ": "l",  # U+04CF
    "в": "b",
    "м": "m",
    "т": "t",
    "к": "k",
    "н": "h",
    # Greek lookalikes
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "ν": "v",
    "τ": "t",
    "ι": "i",
    "κ": "k",
    "ε": "e",
    "χ": "x",
    "υ": "u",
    "ѡ": "w",
    # Latin extended / accented that fold to a base letter
    "ł": "l",
    "ø": "o",
    "đ": "d",
    "ı": "i",
    "ɩ": "l",
    "ɑ": "a",
    "ǝ": "e",
}


def _apply_multichar(text: str) -> str:
    result = []
    i = 0
    keys = sorted(MULTI_CHAR, key=len, reverse=True)
    while i < len(text):
        for k in keys:
            if text.startswith(k, i):
                result.append(MULTI_CHAR[k])
                i += len(k)
                break
        else:
            result.append(text[i])
            i += 1
    return "".join(result)


def skeleton(label: str) -> str:
    """Fold a label to its confusable skeleton (lowercase ASCII where possible).

    ``paypa1`` -> ``paypal``; Cyrillic ``pаypаl`` -> ``paypal``; ``paypa1-rn`` ->
    ``paypal-m``. Characters with no mapping are passed through lowercased.
    """
    # NFKC first so fullwidth / compatibility forms collapse to their base.
    text = unicodedata.normalize("NFKC", label).lower()
    text = _apply_multichar(text)
    out = []
    for ch in text:
        if ch in SINGLE_CHAR:
            out.append(SINGLE_CHAR[ch])
        else:
            out.append(ch)
    return "".join(out)


def has_confusable(label: str) -> bool:
    """True if the label contains any character that our tables would remap
    (i.e. it is not already plain ASCII lowercase letters/hyphen/digits that map
    to themselves)."""
    text = unicodedata.normalize("NFKC", label).lower()
    if any(ch in SINGLE_CHAR for ch in text):
        return True
    for k in MULTI_CHAR:
        if k in text:
            return True
    return False


def is_non_ascii(label: str) -> bool:
    return any(ord(ch) > 127 for ch in label)
