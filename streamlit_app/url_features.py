import ipaddress
import re
import tldextract

LEXICAL_FEATURE_COLS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]

# Avoid live network suffix fetches at runtime for instant offline-safe execution
_NO_FETCH_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)

def extract_url_lexical_features(url: str) -> dict:
    """Compute URL-only lexical features deterministically without network access."""
    url_str = "" if url is None else str(url).strip()
    url_len = len(url_str)

    no_scheme = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url_str)
    host_part = no_scheme.split("/")[0].split("?")[0].split("#")[0]
    host_no_port = host_part.split(":")[0]

    ext = _NO_FETCH_EXTRACT(url_str)
    domain_full = host_no_port
    tld_str = ext.suffix or ""

    is_ip = 0
    try:
        ipaddress.ip_address(host_no_port.strip("[]"))
        is_ip = 1
    except ValueError:
        is_ip = 0

    if is_ip or not ext.domain:
        no_subdomain = 0
    else:
        sub_parts = [p for p in ext.subdomain.split(".") if p and p.lower() != "www"]
        no_subdomain = len(sub_parts)

    letters = sum(c.isalpha() for c in url_str)
    digits = sum(c.isdigit() for c in url_str)
    equals = url_str.count("=")
    qmarks = url_str.count("?")
    ampersands = url_str.count("&")

    pct_matches = re.findall(r"%[0-9a-fA-F]{2}", url_str)
    obf_chars = len(pct_matches) * 3 + url_str.count("@")
    has_obf = 1 if obf_chars > 0 else 0
    obf_ratio = round(obf_chars / url_len, 6) if url_len > 0 else 0.0

    other_special = sum(
        (not c.isalnum()) and (c not in {"=", "?", "&"})
        for c in url_str
    )

    letter_ratio = round(letters / url_len, 6) if url_len > 0 else 0.0
    digit_ratio = round(digits / url_len, 6) if url_len > 0 else 0.0
    special_total = sum(not c.isalnum() for c in url_str)
    special_ratio = round(special_total / url_len, 6) if url_len > 0 else 0.0

    is_https = 1 if url_str.lower().startswith("https://") else 0

    return {
        "URLLength": url_len,
        "DomainLength": len(domain_full),
        "IsDomainIP": is_ip,
        "TLDLength": len(tld_str),
        "NoOfSubDomain": no_subdomain,
        "HasObfuscation": has_obf,
        "NoOfObfuscatedChar": obf_chars,
        "ObfuscationRatio": obf_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": equals,
        "NoOfQMarkInURL": qmarks,
        "NoOfAmpersandInURL": ampersands,
        "NoOfOtherSpecialCharsInURL": other_special,
        "SpacialCharRatioInURL": special_ratio,
        "IsHTTPS": is_https,
    }
