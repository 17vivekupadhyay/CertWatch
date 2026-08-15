"""DGA (domain-generation-algorithm) heuristics.

A label like ``x7fj29dkq2`` is machine-generated: high Shannon entropy, no
recognizable dictionary words, long runs of consonants. A label like
``paypal`` or ``northwind-supplies`` is human-chosen and should not fire.

We combine three cheap signals so no single one dominates:
  * Shannon entropy per character
  * dictionary-word coverage (fraction of the label explained by common words)
  * longest consonant run
"""

import math

# Small embedded word list — enough to recognise that ordinary domains are made
# of real words without shipping a megabyte dictionary. Tuned for coverage of
# the fragments that show up in legitimate domain names.
_COMMON_WORDS = {
    "the", "and", "for", "you", "get", "app", "web", "net", "dev", "cloud",
    "shop", "store", "online", "secure", "login", "mail", "home", "page",
    "site", "blog", "news", "info", "help", "support", "service", "services",
    "account", "bank", "pay", "card", "money", "gold", "silver", "green",
    "blue", "red", "black", "white", "north", "south", "east", "west", "wind",
    "supplies", "supply", "group", "team", "media", "digital", "tech", "data",
    "soft", "ware", "systems", "solutions", "global", "world", "prime",
    "market", "trade", "capital", "fund", "invest", "health", "care", "med",
    "food", "auto", "car", "home", "house", "build", "works", "labs", "lab",
    "studio", "design", "art", "photo", "music", "game", "games", "play",
    "book", "books", "learn", "school", "academy", "center", "central",
    "city", "town", "land", "park", "river", "lake", "hill", "valley", "star",
    "sun", "moon", "sky", "sea", "wave", "fire", "ice", "stone", "rock",
    "iron", "steel", "oak", "pine", "rose", "lily", "fox", "wolf", "bear",
    "eagle", "hawk", "lion", "tiger", "swift", "rapid", "quick", "fast",
    "smart", "bright", "clear", "pure", "fresh", "new", "old", "big", "top",
    "best", "first", "next", "one", "two", "max", "pro", "plus", "hub",
    "spot", "zone", "point", "line", "link", "connect", "network", "portal",
    "gateway", "access", "direct", "express", "flow", "stream", "sync",
    "cyber", "byte", "bit", "code", "logic", "core", "edge", "peak", "apex",
    "nova", "orbit", "pixel", "vector", "matrix", "atlas", "delta", "alpha",
    "beta", "gamma", "omega", "prime", "vault", "forge", "anchor", "bridge",
}

_VOWELS = set("aeiou")


def is_common_word(label: str) -> bool:
    """True if the label is a single, plain dictionary word. Used to stop a
    common word (``cloud``) from being read as a brand lookalike of a token
    that is just a prefix + that word (``gcloud``, ``icloud``)."""
    return label.lower() in _COMMON_WORDS


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def longest_consonant_run(text: str) -> int:
    best = run = 0
    for ch in text:
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def word_coverage(label: str) -> float:
    """Fraction of the label's characters explained by dictionary words found
    as substrings (greedy, longest-first). ``northwind`` -> ~1.0 (north+wind);
    ``x7fj29dkq2`` -> ~0.0."""
    text = "".join(ch for ch in label.lower() if ch.isalpha())
    if not text:
        return 0.0
    covered = [False] * len(text)
    words = sorted(_COMMON_WORDS, key=len, reverse=True)
    for w in words:
        if len(w) < 3:
            continue
        start = 0
        while True:
            idx = text.find(w, start)
            if idx == -1:
                break
            for j in range(idx, idx + len(w)):
                covered[j] = True
            start = idx + 1
    return sum(covered) / len(text)


def dga_score(label: str) -> dict:
    """Return a dict describing how DGA-like the label looks and whether it
    crosses the firing threshold.

    ``looks_dga`` is the boolean the scorer uses. The component metrics are kept
    for the detail string so an analyst can see *why*.
    """
    core = "".join(ch for ch in label.lower() if ch.isalnum())
    entropy = shannon_entropy(core)
    coverage = word_coverage(label)
    consonants = longest_consonant_run(label)
    digits = sum(ch.isdigit() for ch in core)
    length = len(core)

    # Short labels are noisy; require some length before judging.
    looks_dga = (
        length >= 8
        and entropy >= 3.0
        and coverage < 0.35
        and (consonants >= 4 or digits >= 3)
    )

    return {
        "looks_dga": looks_dga,
        "entropy": round(entropy, 2),
        "coverage": round(coverage, 2),
        "consonant_run": consonants,
        "digits": digits,
    }
