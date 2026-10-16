"""
Office Macro Analyzer

Uses oletools to inspect Microsoft Office documents
for VBA macros.

This is STATIC analysis.

The document is inspected but NOT executed.
"""

from pathlib import Path

from oletools.olevba import VBA_Parser


def analyze_macros(file_path):
    """
    Inspect an Office document for VBA macros.

    Returns:
        Macro presence and basic macro information.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    result = {
        "filename": path.name,
        "has_vba": False,
        "macro_count": 0,
        "macros": [],
    }

    try:

        # Create the VBA parser.
        vba_parser = VBA_Parser(
            str(path)
        )

        # Check whether VBA macros exist.
        if vba_parser.detect_vba_macros():

            result["has_vba"] = True

            # Extract information about each macro.
            for (
                filename,
                stream_path,
                vba_filename,
                code
            ) in vba_parser.extract_macros():

                result["macro_count"] += 1

                result["macros"].append({
                    "filename": filename,
                    "stream": stream_path,
                    "vba_filename": vba_filename,
                    "code_length": len(code),
                })

        vba_parser.close()

    except Exception as error:

        result["error"] = str(error)

    return result


def main():
    """
    Test macro analysis.
    """

    TEST_FILE = "data/raw/test_attachment.docm"

    result = analyze_macros(
        TEST_FILE
    )

    print("\n========== MACRO ANALYSIS ==========")

    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
