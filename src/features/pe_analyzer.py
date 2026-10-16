"""
Static PE Malware Analyzer

Analyzes Windows Portable Executable (PE) files without
executing them.

Extracts:
- PE type
- Machine architecture
- Number of sections
- Section names
- Section entropy
- Imported DLLs
- Imported APIs
- Suspicious Windows APIs
- Entry point
- Image base
- SHA-256

This information will later become features for the
static malware detection model.

IMPORTANT:
This module does NOT execute the file.
"""

import hashlib
from pathlib import Path

import pefile


# Windows APIs that can be useful signals during
# malware analysis.

SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "OpenProcess",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "CreateProcessA",
    "CreateProcessW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "RegCreateKeyA",
    "RegCreateKeyW",
    "RegSetValueA",
    "RegSetValueW",
    "CreateServiceA",
    "CreateServiceW",
}


def calculate_sha256(file_path):
    """
    Calculate SHA-256 hash of the PE file.

    The file is read in chunks to avoid loading the entire
    file into memory.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def analyze_sections(pe):
    """
    Extract PE section information.

    Entropy can be useful as a static signal because
    packed/encrypted sections may have unusually high
    entropy.

    High entropy alone does NOT mean malware.
    """

    sections = []

    for section in pe.sections:

        name = (
            section.Name
            .decode(
                errors="ignore"
            )
            .rstrip("\x00")
        )

        entropy = section.get_entropy()

        sections.append({
            "name": name,
            "virtual_address": hex(
                section.VirtualAddress
            ),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": round(
                entropy,
                4
            ),
        })

    return sections


def analyze_imports(pe):
    """
    Extract imported DLLs and API functions.

    Imported APIs can provide useful behavioral clues
    for static malware analysis.
    """

    imported_dlls = []
    imported_apis = []
    suspicious_apis = []

    if not hasattr(
        pe,
        "DIRECTORY_ENTRY_IMPORT"
    ):
        return {
            "dlls": [],
            "apis": [],
            "suspicious_apis": []
        }

    for entry in pe.DIRECTORY_ENTRY_IMPORT:

        dll_name = entry.dll.decode(
            errors="ignore"
        )

        imported_dlls.append(
            dll_name
        )

        for imported in entry.imports:

            if imported.name:

                api_name = (
                    imported.name
                    .decode(
                        errors="ignore"
                    )
                )

                imported_apis.append(
                    api_name
                )

                if api_name in SUSPICIOUS_APIS:

                    suspicious_apis.append(
                        api_name
                    )

    return {
        "dlls": sorted(
            set(imported_dlls)
        ),
        "apis": sorted(
            set(imported_apis)
        ),
        "suspicious_apis": sorted(
            set(suspicious_apis)
        ),
    }


def analyze_pe(file_path):
    """
    Perform complete static PE analysis.

    The file is parsed but never executed.
    """

    path = Path(file_path)

    if not path.exists():

        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    # Calculate file hash before analysis.
    sha256 = calculate_sha256(
        path
    )

    try:

        # Parse the PE file.
        pe = pefile.PE(
            str(path)
        )

    except pefile.PEFormatError as error:

        return {
            "success": False,
            "error": (
                f"Not a valid PE file: {error}"
            )
        }

    # Basic PE information.
    machine = hex(
        pe.FILE_HEADER.Machine
    )

    number_of_sections = (
        pe.FILE_HEADER.NumberOfSections
    )

    entry_point = hex(
        pe.OPTIONAL_HEADER.AddressOfEntryPoint
    )

    image_base = hex(
        pe.OPTIONAL_HEADER.ImageBase
    )

    # Analyze sections.
    sections = analyze_sections(
        pe
    )

    # Analyze imports.
    imports = analyze_imports(
        pe
    )

    result = {
        "success": True,
        "filename": path.name,
        "sha256": sha256,
        "file_size": path.stat().st_size,

        "machine": machine,
        "number_of_sections": number_of_sections,
        "entry_point": entry_point,
        "image_base": image_base,

        "sections": sections,

        "imports": imports,

        # Convenient summary features that can later
        # become ML features.
        "suspicious_api_count": len(
            imports["suspicious_apis"]
        ),

        "high_entropy_sections": [
            section["name"]
            for section in sections
            if section["entropy"] >= 7.0
        ],
    }

    # Release the parsed PE object.
    pe.close()

    return result


def print_analysis(result):
    """
    Print PE analysis in a human-readable format.
    """

    print(
        "\n" + "=" * 70
    )

    print(
        "             STATIC PE MALWARE ANALYSIS"
    )

    print(
        "=" * 70
    )

    if not result.get("success"):

        print(
            "\nERROR:",
            result.get("error")
        )

        return

    print(
        "\nFilename:",
        result["filename"]
    )

    print(
        "SHA-256:",
        result["sha256"]
    )

    print(
        "File size:",
        result["file_size"]
    )

    print(
        "Machine:",
        result["machine"]
    )

    print(
        "Number of sections:",
        result["number_of_sections"]
    )

    print(
        "Entry point:",
        result["entry_point"]
    )

    print(
        "Image base:",
        result["image_base"]
    )

    print(
        "\nSections:"
    )

    for section in result["sections"]:

        print(
            f"  {section['name']} | "
            f"entropy={section['entropy']} | "
            f"raw_size={section['raw_size']}"
        )

    print(
        "\nImported DLLs:"
    )

    for dll in result["imports"]["dlls"]:

        print(
            f"  {dll}"
        )

    print(
        "\nSuspicious APIs:"
    )

    suspicious = result[
        "imports"
    ]["suspicious_apis"]

    if suspicious:

        for api in suspicious:
            print(
                f"  {api}"
            )

    else:

        print(
            "  None detected"
        )

    print(
        "\nHigh-entropy sections:"
    )

    print(
        result["high_entropy_sections"]
    )


def main():
    """
    Test the PE analyzer.

    Use a known-safe Windows executable for initial
    testing rather than an unknown malware sample.
    """

    test_file = (
        "data/raw/test.exe"
    )

    if not Path(
        test_file
    ).exists():

        print(
            f"File not found: {test_file}"
        )

        print(
            "\nPlace a known-safe PE executable at:"
        )

        print(
            test_file
        )

        return

    result = analyze_pe(
        test_file
    )

    print_analysis(
        result
    )


if __name__ == "__main__":
    main()
