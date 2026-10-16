"""
Attachment Embedded URL Analyzer

Extracts URLs from supported attachment formats and sends
them through the central URL analyzer.

Supported:
- PDF
- DOCX
- XLSX
- PPTX
- HTML
- TXT

The extracted URLs are NOT analyzed separately.

Every URL is passed to:

    src/features/url_analyzer.py

Therefore the same URL intelligence is applied to:
- direct URLs
- email URLs
- QR URLs
- attachment URLs
"""

import re
from pathlib import Path

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    from docx import Document
except ImportError:
    Document = None

try:
    from openpyxl import load_workbook
except ImportError:
    load_workbook = None

try:
    from pptx import Presentation
except ImportError:
    Presentation = None

from bs4 import BeautifulSoup

from src.features.url_analyzer import analyze_url


# Detect HTTP/HTTPS URLs.
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE
)


def extract_urls_from_text(text):
    """
    Extract HTTP/HTTPS URLs from text.
    """

    if not text:
        return []

    return URL_PATTERN.findall(text)


def extract_from_pdf(file_path):
    """
    Extract URLs from PDF text.

    This checks visible text first.
    """
    if PdfReader is None:
        try:
            raw_text = Path(file_path).read_bytes().decode("latin1", errors="ignore")
            return extract_urls_from_text(raw_text)
        except Exception:
            return []

    urls = []

    try:
        reader = PdfReader(str(file_path))
        for page in reader.pages:
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            urls.extend(extract_urls_from_text(text))
    except Exception:
        pass

    return urls


def extract_from_docx(file_path):
    """
    Extract URLs from DOCX paragraphs.

    It checks both visible text and hyperlinks
    stored inside the document XML.
    """
    if Document is None:
        try:
            raw_text = Path(file_path).read_bytes().decode("latin1", errors="ignore")
            return extract_urls_from_text(raw_text)
        except Exception:
            return []

    urls = []

    try:
        document = Document(str(file_path))
        for paragraph in document.paragraphs:
            urls.extend(extract_urls_from_text(paragraph.text))
        for relationship in document.part.rels.values():
            if relationship.reltype.endswith("/hyperlink"):
                target = relationship.target_ref
                if target.startswith(("http://", "https://")):
                    urls.append(target)
    except Exception:
        pass

    return urls


def extract_from_xlsx(file_path):
    """
    Extract URLs from Excel workbook cells
    and hyperlinks.
    """
    if load_workbook is None:
        try:
            raw_text = Path(file_path).read_bytes().decode("latin1", errors="ignore")
            return extract_urls_from_text(raw_text)
        except Exception:
            return []

    urls = []

    try:
        workbook = load_workbook(
            filename=str(file_path),
            read_only=True,
            data_only=False
        )

        for worksheet in workbook.worksheets:
            for row in worksheet.iter_rows():
                for cell in row:
                    if isinstance(cell.value, str):
                        urls.extend(extract_urls_from_text(cell.value))
                    if cell.hyperlink:
                        target = cell.hyperlink.target
                        if target and target.startswith(("http://", "https://")):
                            urls.append(target)

        workbook.close()
    except Exception:
        pass

    return urls


def extract_from_pptx(file_path):
    """
    Extract URLs from PowerPoint text
    and hyperlinks.
    """
    if Presentation is None:
        try:
            raw_text = Path(file_path).read_bytes().decode("latin1", errors="ignore")
            return extract_urls_from_text(raw_text)
        except Exception:
            return []

    urls = []

    try:
        presentation = Presentation(str(file_path))
        for slide in presentation.slides:
            for shape in slide.shapes:
                if hasattr(shape, "text"):
                    urls.extend(extract_urls_from_text(shape.text))
                if hasattr(shape, "text_frame"):
                    for paragraph in shape.text_frame.paragraphs:
                        for run in paragraph.runs:
                            if hasattr(run, "hyperlink") and run.hyperlink and getattr(run.hyperlink, "address", None):
                                target = run.hyperlink.address
                                if target.startswith(("http://", "https://")):
                                    urls.append(target)
    except Exception:
        pass

    return urls


def extract_from_html(file_path):
    """
    Extract URLs from HTML text and href attributes.
    """

    html = Path(
        file_path
    ).read_text(
        encoding="utf-8",
        errors="ignore"
    )

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    urls = []

    # URLs appearing directly in visible text.
    urls.extend(
        extract_urls_from_text(
            soup.get_text(" ")
        )
    )

    # URLs contained inside href attributes.
    for anchor in soup.find_all(
        "a",
        href=True
    ):

        href = anchor.get(
            "href"
        )

        if href.startswith(
            ("http://", "https://")
        ):
            urls.append(href)

    return urls


def extract_from_txt(file_path):
    """
    Extract URLs from a plain-text file.
    """

    text = Path(
        file_path
    ).read_text(
        encoding="utf-8",
        errors="ignore"
    )

    return extract_urls_from_text(
        text
    )


def extract_embedded_urls(file_path):
    """
    Determine the attachment type and extract URLs.

    Returns:
        A list of discovered URLs.
    """

    path = Path(
        file_path
    )

    extension = path.suffix.lower()

    if extension == ".pdf":
        urls = extract_from_pdf(
            path
        )

    elif extension == ".docx":
        urls = extract_from_docx(
            path
        )

    elif extension in (
        ".xlsx",
        ".xlsm"
    ):
        urls = extract_from_xlsx(
            path
        )

    elif extension in (
        ".pptx",
        ".pptm"
    ):
        urls = extract_from_pptx(
            path
        )

    elif extension in (
        ".html",
        ".htm"
    ):
        urls = extract_from_html(
            path
        )

    elif extension == ".txt":
        urls = extract_from_txt(
            path
        )

    else:
        return []

    # Remove duplicates while preserving order.
    unique_urls = list(
        dict.fromkeys(urls)
    )

    return unique_urls


def analyze_attachment_urls(file_path):
    """
    Extract embedded URLs and send every URL through
    the central URL intelligence pipeline.
    """

    urls = extract_embedded_urls(
        file_path
    )

    results = []

    for url in urls:

        # Central URL analysis.
        analysis = analyze_url(
            url
        )

        results.append({
            "source_file": str(
                file_path
            ),
            "embedded_url": url,
            "url_analysis": analysis
        })

    return results


def main():
    """
    Test embedded URL extraction.

    Change this to a harmless attachment you have.
    """

    test_file = (
        "data/raw/test_attachment.pdf"
    )

    if not Path(
        test_file
    ).exists():

        print(
            f"File not found: {test_file}"
        )

        return

    results = analyze_attachment_urls(
        test_file
    )

    print(
        "\n========== EMBEDDED URL ANALYSIS =========="
    )

    if not results:

        print(
            "No HTTP/HTTPS URLs found."
        )

        return

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
            "Source file:",
            result["source_file"]
        )

        print(
            "Embedded URL:",
            result["embedded_url"]
        )

        print(
            "\nURL intelligence:"
        )

        analysis = result[
            "url_analysis"
        ]

        for section, data in analysis.items():

            print(
                f"\n[{section.upper()}]"
            )

            if isinstance(
                data,
                dict
            ):

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


def extract_urls_from_attachment(file_path):
    """Compatibility wrapper for legacy import.

    Historically the unified analyzer imported `extract_urls_from_attachment`
    from this module. The actual implementation is `extract_embedded_urls`.
    This wrapper simply forwards the call.
    """
    return extract_embedded_urls(file_path)
