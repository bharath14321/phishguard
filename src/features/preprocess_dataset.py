import pandas as pd


INPUT_FILE = "data/raw/malicious_phish.csv"
OUTPUT_FILE = "data/processed/clean_urls.csv"


VALID_TYPES = {
    "benign",
    "defacement",
    "phishing",
    "malware"
}


def main():

    df = pd.read_csv(INPUT_FILE)

    print("Original shape:", df.shape)

    # Keep required columns
    df = df[["url", "type"]]

    # Remove missing values
    df = df.dropna(subset=["url", "type"])

    # Normalize text
    df["url"] = df["url"].astype(str).str.strip()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    # Keep only expected labels
    df = df[df["type"].isin(VALID_TYPES)]

    # Remove empty URLs
    df = df[df["url"] != ""]

    # Remove duplicate URL-label combinations
    df = df.drop_duplicates(subset=["url", "type"])

    print("\nAfter cleaning:", df.shape)

    print("\nClass distribution:")
    print(df["type"].value_counts())

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\nSaved:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
