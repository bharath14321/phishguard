"""
Email URL Extraction and Analysis

This module extracts URLs from email messages and sends
each discovered URL to the central URL analysis pipeline.

The central URL analyzer performs:

- URL lexical analysis
- Domain intelligence
- Brand intelligence
- IP intelligence
- VirusTotal reputation
- Redirect analysis

This means URLs found in emails receive exactly the same
analysis as directly submitted URLs.
"""

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

# Import the central URL analysis pipeline.
from src.features.url_analyzer import analyze_url


# Regular expression for HTTP/HTTPS URLs.
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


def extract_plain_text_urls(text):
    """
    Extract HTTP/HTTPS URLs from plain-text email content.

    Returns:
        A list of URLs.
    """

    if not text:
        return []

    return URL_PATTERN.findall(text)


def extract_html_urls(html):
    """
    Extract HTTP/HTTPS links from HTML email content.

    For every link we collect:
    - visible text
    - actual href destination
    """

    if not html:
        return []

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    links = []

    for anchor in soup.find_all(
        "a",
        href=True
    ):

        href = anchor.get(
            "href",
            ""
        ).strip()

        # We only want HTTP/HTTPS URLs.
        if not href.lower().startswith(
            ("http://", "https://")
        ):
            continue

        # Text displayed to the email recipient.
        visible_text = anchor.get_text(
            " ",
            strip=True
        )

        links.append({
            "visible_text": visible_text,
            "url": href
        })

    return links


def detect_visible_url_mismatch(
    visible_text,
    destination_url
):
    """
    Check whether the visible URL shown to the user
    points to a different domain than the actual href.

    Example:

        Visible:
        https://paypal.com/login

        Actual:
        https://evil-example.com/login

    Result:
        True

    This is a phishing signal, not a final verdict.
    """

    # Find URLs displayed as visible text.
    visible_urls = URL_PATTERN.findall(
        visible_text or ""
    )

    if not visible_urls:
        return False

    # Extract the visible URL's hostname.
    visible_domain = urlparse(
        visible_urls[0]
    ).hostname

    # Extract the actual destination hostname.
    destination_domain = urlparse(
        destination_url
    ).hostname

    if not visible_domain or not destination_domain:
        return False

    return (
        visible_domain.lower()
        != destination_domain.lower()
    )


def analyze_email_urls(
    plain_text,
    html
):
    """
    Extract URLs from both plain-text and HTML email content.

    Every unique URL is then passed to the central
    URL analyzer.

    Returns:
        A list containing complete URL intelligence.
    """

    discovered_urls = []

    # --------------------------------------------------
    # 1. Extract URLs from plain-text email.
    # --------------------------------------------------

    plain_urls = extract_plain_text_urls(
        plain_text
    )

    for url in plain_urls:

        discovered_urls.append({
            "source": "plain_text",
            "url": url,
            "visible_text": None,
            "domain_mismatch": False
        })

    # --------------------------------------------------
    # 2. Extract URLs from HTML email.
    # --------------------------------------------------

    html_links = extract_html_urls(
        html
    )

    for link in html_links:

        mismatch = detect_visible_url_mismatch(
            link["visible_text"],
            link["url"]
        )

        discovered_urls.append({
            "source": "html",
            "url": link["url"],
            "visible_text": link["visible_text"],
            "domain_mismatch": mismatch
        })

    # --------------------------------------------------
    # 3. Remove duplicate URLs.
    # --------------------------------------------------

    unique_urls = []

    seen = set()

    for item in discovered_urls:

        url = item["url"]

        if url not in seen:

            seen.add(url)

            unique_urls.append(
                item
            )

    # --------------------------------------------------
    # 4. Send every URL to the central analyzer.
    # --------------------------------------------------

    results = []

    for item in unique_urls:

        # This is the important integration point.
        #
        # URL → url_analyzer.py
        #
        # url_analyzer then performs:
        # URL features
        # Domain intelligence
        # Brand intelligence
        # IP intelligence
        # VirusTotal
        # Redirect analysis

        url_analysis = analyze_url(
            item["url"]
        )

        # Combine email-specific information
        # with the complete URL analysis.
        result = {
            "source": item["source"],
            "url": item["url"],
            "visible_text": item["visible_text"],
            "domain_mismatch": item[
                "domain_mismatch"
            ],
            "url_analysis": url_analysis
        }

        results.append(
            result
        )

    return results


def main():
    """
    Test email URL extraction and automatic URL analysis.
    """

    # Example plain-text email.
    plain_text = """
    Your account requires verification.

    Please visit:
    https://example.org/login
    """

    # Example HTML email containing a deceptive link.
    html = """
    <html>
        <body>

            <p>
                Your account requires verification.
            </p>

            <a href="https://evil-example.com/login">
                https://paypal.com/login
            </a>

            <br>

            <a href="https://example.com">
                Visit Example
            </a>

        </body>
    </html>
    """

    results = analyze_email_urls(
        plain_text,
        html
    )

    print(
        "\n========== EMAIL URL ANALYSIS =========="
    )

    for index, result in enumerate(
        results,
        start=1
    ):

        print(
            f"\n{'=' * 60}"
        )

        print(
            f"URL #{index}"
        )

        print(
            "Source:",
            result["source"]
        )

        print(
            "URL:",
            result["url"]
        )

        print(
            "Visible text:",
            result["visible_text"]
        )

        print(
            "Visible/actual domain mismatch:",
            result["domain_mismatch"]
        )

        print(
            "\nComplete URL Analysis:"
        )

        analysis = result[
            "url_analysis"
        ]

        # Print each intelligence layer.
        for section, data in analysis.items():

            print(
                f"\n[{section.upper()}]"
            )

            if isinstance(data, dict):

                for key, value in data.items():
                    print(
                        f"  {key}: {value}"
                    )

            else:
                print(
                    f"  {data}"
                )


if __name__ == "__main__":
    main()
