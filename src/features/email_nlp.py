"""
Email NLP / Social Engineering Analysis

Extracts linguistic signals commonly associated with
phishing and Business Email Compromise (BEC).

This is intentionally rule-based for the first version.
Later we can replace/augment it with a trained NLP model
or an LLM-based analysis layer.
"""

import re


# Words/phrases associated with urgency.
URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bas soon as possible\b",
    r"\baction required\b",
    r"\bact now\b",
    r"\bwithin \d+ hours?\b",
    r"\bwithin \d+ minutes?\b",
    r"\bexpires?\b",
    r"\blast warning\b",
    r"\bfinal notice\b",
]


# Language commonly associated with credential theft.
CREDENTIAL_PATTERNS = [
    r"\bpassword\b",
    r"\bverify your account\b",
    r"\bverify your identity\b",
    r"\blogin\b",
    r"\bsign in\b",
    r"\busername\b",
    r"\bcredentials?\b",
    r"\bsecurity verification\b",
    r"\baccount verification\b",
    r"\breset your password\b",
]


# Financial/payment-related language.
FINANCIAL_PATTERNS = [
    r"\bpayment\b",
    r"\binvoice\b",
    r"\bwire transfer\b",
    r"\bbank account\b",
    r"\btransfer funds\b",
    r"\bpayment details\b",
    r"\bcredit card\b",
    r"\bdebit card\b",
    r"\brefund\b",
    r"\btransaction\b",
]


# BEC-style requests.
BEC_PATTERNS = [
    r"\bconfidential\b",
    r"\bkeep this confidential\b",
    r"\bdo not tell\b",
    r"\bdo not share\b",
    r"\bwire\b",
    r"\btransfer\b",
    r"\bgift card\b",
    r"\bceo\b",
    r"\bdirector\b",
    r"\bexecutive\b",
    r"\bsecret\b",
]


# Common call-to-action language.
ACTION_PATTERNS = [
    r"\bclick here\b",
    r"\bclick the link\b",
    r"\bclick below\b",
    r"\bopen the attachment\b",
    r"\bdownload\b",
    r"\bverify\b",
    r"\bconfirm\b",
    r"\bupdate your account\b",
]


def count_pattern_matches(text, patterns):
    """
    Count how many patterns are present in the text.

    Each pattern contributes at most one match.
    """

    count = 0
    matched_patterns = []

    for pattern in patterns:

        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            count += 1
            matched_patterns.append(pattern)

    return count, matched_patterns


def calculate_text_statistics(text):
    """
    Calculate basic text statistics.

    These can later be used as NLP/ML features.
    """

    words = re.findall(
        r"\b\w+\b",
        text
    )

    sentences = re.split(
        r"[.!?]+",
        text
    )

    return {
        "character_count": len(text),
        "word_count": len(words),
        "sentence_count": len(
            [s for s in sentences if s.strip()]
        ),
        "uppercase_ratio": (
            sum(1 for char in text if char.isupper())
            / max(1, sum(1 for char in text if char.isalpha()))
        ),
        "exclamation_count": text.count("!"),
    }


def analyze_email_language(text):
    """
    Analyze the language of an email.

    Returns:
        Linguistic features and matched categories.
    """

    if not text:
        text = ""

    urgency_count, urgency_matches = (
        count_pattern_matches(
            text,
            URGENCY_PATTERNS
        )
    )

    credential_count, credential_matches = (
        count_pattern_matches(
            text,
            CREDENTIAL_PATTERNS
        )
    )

    financial_count, financial_matches = (
        count_pattern_matches(
            text,
            FINANCIAL_PATTERNS
        )
    )

    bec_count, bec_matches = (
        count_pattern_matches(
            text,
            BEC_PATTERNS
        )
    )

    action_count, action_matches = (
        count_pattern_matches(
            text,
            ACTION_PATTERNS
        )
    )

    statistics = calculate_text_statistics(
        text
    )

    return {
        "statistics": statistics,

        "urgency_count": urgency_count,
        "credential_count": credential_count,
        "financial_count": financial_count,
        "bec_count": bec_count,
        "action_count": action_count,

        "matched_categories": {
            "urgency": urgency_matches,
            "credentials": credential_matches,
            "financial": financial_matches,
            "bec": bec_matches,
            "actions": action_matches,
        }
    }


def analyze_email_subject_and_body(
    subject,
    body
):
    """
    Analyze both subject and body.

    Combining them gives the later risk engine
    more context than analyzing the body alone.
    """

    combined_text = (
        f"{subject}\n{body}"
    )

    return analyze_email_language(
        combined_text
    )


def main():
    """
    Test the NLP analyzer with a simulated phishing email.
    """

    subject = (
        "URGENT: Your account requires "
        "immediate verification"
    )

    body = """
    Your account will be suspended immediately.

    Please click the link below and verify
    your password within 24 hours.

    Failure to act may result in account closure.
    """

    result = analyze_email_subject_and_body(
        subject,
        body
    )

    print("\n========== EMAIL NLP ANALYSIS ==========")

    for key, value in result.items():
        print(f"\n{key}: {value}")


if __name__ == "__main__":
    main()
