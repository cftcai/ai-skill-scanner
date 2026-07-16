"""Shannon entropy helper for obfuscation detection."""
import math


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Values >4.5 often indicate encoded payloads."""
    if not data or len(data) < 20:
        return 0.0
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
