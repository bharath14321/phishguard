import pandas as pd
from src.features.url_features import extract_url_features

INPUT_FILE = "data/processed/clean_urls.csv"
OUTPUT_FILE = "data/processed/url_features.csv"

MULTICLASS_MAPPING = {
    "benign": 0,
    "defacement": 1,
    "phishing": 2,
    "malware": 3
}


def build_dataset():

    print("Loading cleaned dataset...")

    df = pd.read_csv(INPUT_FILE)

    print(f"Input samples: {len(df)}")

    feature_rows = []

    for i, row in enumerate(df.itertuples(index=False), start=1):

        url = row.url
        label_type = row.type

        try:
            features = extract_url_features(url)

            # Keep original information
            features["url"] = url
            features["type"] = label_type

            # Binary classification:
            # benign = 0
            # everything else = 1
            features["binary_label"] = int(label_type != "benign")

            # Multiclass classification
            features["multiclass_label"] = MULTICLASS_MAPPING[label_type]

            feature_rows.append(features)

        except Exception as e:
            print(f"Error processing URL: {url}")
            print(f"Reason: {e}")

        if i % 10000 == 0:
            print(f"Processed: {i}/{len(df)}")

    features_df = pd.DataFrame(feature_rows)

    features_df.to_csv(OUTPUT_FILE, index=False)

    print("\nFeature dataset created successfully.")
    print(f"Samples: {len(features_df)}")
    print(f"Features: {len(features_df.columns)}")

    print("\nBinary distribution:")
    print(features_df["binary_label"].value_counts())

    print("\nMulticlass distribution:")
    print(features_df["multiclass_label"].value_counts())

    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_dataset()
