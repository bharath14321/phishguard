"""
Adversarial URL Testing

Purpose:
    Test whether controlled modifications to URLs can change the
    prediction made by our URL-based Random Forest model.

Important:
    This experiment does NOT send requests to any generated URLs.
    It only modifies URL strings and passes them through our
    local feature extractor and ML model.
"""

import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Import our existing URL feature extraction function.
from src.features.url_features import extract_url_features


# ================================================================
# Configuration
# ================================================================

DATA_FILE = "data/processed/url_features.csv"

OUTPUT_FILE = "data/processed/adversarial_results.csv"

RANDOM_STATE = 42

# These MUST match the 14 features used to train our baseline model.
FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "subdomain_count",
    "contains_ip",
    "uses_https",
    "contains_at",
    "contains_double_slash",
    "suspicious_keyword_count",
]


# ================================================================
# Adversarial transformations
# ================================================================

def add_subdomain(url):
    """
    Add an additional subdomain to the hostname.

    Example:
        example.com/login
        ->
        secure.example.com/login

    Purpose:
        Tests whether additional subdomain depth changes
        the model's prediction.
    """

    # If the URL does not contain a scheme, add the subdomain
    # directly to the beginning of the hostname.
    if "://" not in url:
        return "secure." + url

    # Separate scheme from the remaining URL.
    scheme, rest = url.split("://", 1)

    # Separate hostname from path.
    parts = rest.split("/", 1)

    hostname = parts[0]

    # Preserve the original path if one exists.
    if len(parts) == 2:
        path = "/" + parts[1]
    else:
        path = ""

    return f"{scheme}://secure.{hostname}{path}"


def add_path(url):
    """
    Add an additional path component.

    Example:
        example.com/login
        ->
        example.com/login/account
    """

    if url.endswith("/"):
        return url + "account"

    return url.rstrip("/") + "/account"


def add_query_parameter(url):
    """
    Add a benign query parameter.

    Example:
        example.com/login
        ->
        example.com/login?session=12345

    Purpose:
        Tests the effect of increasing query-string complexity.
    """

    # Use '&' if the URL already contains a query string.
    separator = "&" if "?" in url else "?"

    return url + separator + "session=12345"


def increase_subdomain_depth(url):
    """
    Add several subdomain levels.

    Example:
        example.com
        ->
        login.secure.account.example.com

    Purpose:
        Tests model sensitivity to increased subdomain depth.
    """

    if "://" not in url:
        return "login.secure.account." + url

    scheme, rest = url.split("://", 1)

    parts = rest.split("/", 1)

    hostname = parts[0]

    if len(parts) == 2:
        path = "/" + parts[1]
    else:
        path = ""

    return f"{scheme}://login.secure.account.{hostname}{path}"


def add_fragment(url):
    """
    Add a URL fragment.

    Example:
        example.com/login
        ->
        example.com/login#account

    Purpose:
        Tests whether the model reacts to URL fragments.
    """

    # Avoid adding a second fragment.
    if "#" in url:
        return url

    return url + "#account"


def change_case(url):
    """
    Change the case of alphabetic characters.

    Example:
        Example.com/Login
        ->
        eXAMPLE.COM/lOGIN

    Purpose:
        Tests whether the model is sensitive to letter casing.
    """

    return url.swapcase()


def encode_path_character(url):
    """
    Apply a controlled URL-encoding transformation.

    Example:
        example.com/login
        ->
        example.com%2Flogin

    Purpose:
        Tests whether simple encoding changes the model's
        feature representation.

    Note:
        This is only a string-level ML experiment.
        No network request is performed.
    """

    if "://" not in url:
        return url

    scheme, rest = url.split("://", 1)

    if "/" not in rest:
        return url

    hostname, path = rest.split("/", 1)

    return f"{scheme}://{hostname}%2F{path}"


# ================================================================
# Generate adversarial variants
# ================================================================

def generate_variants(url):
    """
    Generate controlled variants of one URL.

    Returns:
        Dictionary containing:
            transformation name -> modified URL
    """

    return {
        "original": url,
        "added_subdomain": add_subdomain(url),
        "added_path": add_path(url),
        "added_query": add_query_parameter(url),
        "deeper_subdomain": increase_subdomain_depth(url),
        "added_fragment": add_fragment(url),
        "case_changed": change_case(url),
        "encoded_path": encode_path_character(url),
    }


# ================================================================
# Extract model features
# ================================================================

def extract_model_features(url):
    """
    Extract the same 14 features used during model training.

    Returns:
        A pandas DataFrame containing one row of features.

    Why DataFrame?

        The Random Forest was trained using a pandas DataFrame
        with named feature columns.

        Returning another DataFrame with the same column names
        prevents scikit-learn's feature-name warning.
    """

    # Extract features from the existing feature extractor.
    features = extract_url_features(url)

    # Create a DataFrame using the exact same feature names
    # and order used during model training.
    feature_df = pd.DataFrame(
        [[features[column] for column in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS
    )

    return feature_df


# ================================================================
# Train Random Forest
# ================================================================

def train_model(df):
    """
    Train the same Random Forest configuration used
    in our baseline experiment.

    Returns:
        Trained RandomForestClassifier.
    """

    # Select the 14 ML features.
    X = df[FEATURE_COLUMNS]

    # Select the binary malicious/benign label.
    y = df["binary_label"]

    # Use exactly the same 80/20 stratified split as our
    # original Random Forest experiment.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print("Training samples:", len(X_train))
    print("Testing samples:", len(X_test))

    # Create the same Random Forest configuration used
    # in our original baseline experiment.
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    # Train the model.
    model.fit(X_train, y_train)

    return model


# ================================================================
# Run adversarial experiment
# ================================================================

def run_experiment(model, urls):
    """
    Apply adversarial transformations to selected URLs.

    For every transformation we record:

        - original URL
        - true label
        - transformation
        - modified URL
        - prediction
        - malicious probability

    No network requests are performed.
    """

    results = []

    # Process every selected URL.
    for original_url, actual_label in urls:

        # Generate all controlled variants.
        variants = generate_variants(original_url)

        # Test every variant.
        for transformation, variant_url in variants.items():

            try:

                # Convert the URL into the 14 ML features.
                features = extract_model_features(variant_url)

                # Predict benign/malicious.
                prediction = int(
                    model.predict(features)[0]
                )

                # Get probability assigned to malicious class.
                probability = float(
                    model.predict_proba(features)[0][1]
                )

                # Store experiment result.
                results.append({
                    "original_url": original_url,
                    "actual_label": actual_label,
                    "transformation": transformation,
                    "variant_url": variant_url,
                    "prediction": prediction,
                    "malicious_probability": probability,
                    "error": ""
                })

            except Exception as error:

                # If feature extraction fails, record the error
                # instead of stopping the entire experiment.
                results.append({
                    "original_url": original_url,
                    "actual_label": actual_label,
                    "transformation": transformation,
                    "variant_url": variant_url,
                    "prediction": -1,
                    "malicious_probability": np.nan,
                    "error": str(error)
                })

    return pd.DataFrame(results)


# ================================================================
# Analyze prediction changes
# ================================================================

def analyze_prediction_changes(results):
    """
    Analyze whether adversarial transformations changed
    the model's prediction compared with the original URL.

    Returns:
        DataFrame containing transformation-level statistics.
    """

    # Keep only successfully processed rows.
    valid_results = results[
        results["prediction"] != -1
    ].copy()

    # Extract predictions for original URLs.
    original_predictions = (
        valid_results[
            valid_results["transformation"] == "original"
        ][
            ["original_url", "prediction"]
        ]
        .rename(columns={
            "prediction": "original_prediction"
        })
    )

    # Join the original prediction back to every transformation.
    valid_results = valid_results.merge(
        original_predictions,
        on="original_url",
        how="left"
    )

    # Determine whether the transformation changed
    # the model's prediction.
    valid_results["prediction_changed"] = (
        valid_results["prediction"]
        != valid_results["original_prediction"]
    )

    # Do not count the original URL as an adversarial change.
    transformed_results = valid_results[
        valid_results["transformation"] != "original"
    ]

    # Calculate change rate for each transformation.
    summary = (
        transformed_results
        .groupby("transformation")
        .agg(
            tests=("prediction", "count"),
            prediction_changes=("prediction_changed", "sum")
        )
        .reset_index()
    )

    # Convert count into percentage.
    summary["change_rate_percent"] = (
        summary["prediction_changes"]
        / summary["tests"]
        * 100
    )

    return summary


# ================================================================
# Main function
# ================================================================

def main():
    """
    Main function.

    Steps:

        1. Load processed dataset.
        2. Train Random Forest.
        3. Select benign and malicious URLs.
        4. Generate controlled adversarial variants.
        5. Run variants through the model.
        6. Save detailed results.
        7. Print transformation-level analysis.
    """

    print("========================================")
    print("ADVERSARIAL URL TESTING")
    print("========================================")

    # ------------------------------------------------------------
    # Load dataset
    # ------------------------------------------------------------

    print("\nLoading dataset...")

    df = pd.read_csv(DATA_FILE)

    print("Dataset size:", len(df))

    # ------------------------------------------------------------
    # Train model
    # ------------------------------------------------------------

    print("\nTraining Random Forest...")

    model = train_model(df)

    # ------------------------------------------------------------
    # Select test URLs
    # ------------------------------------------------------------

    # Select 10 benign URLs.
    benign_samples = (
        df[df["binary_label"] == 0]
        .sample(
            10,
            random_state=RANDOM_STATE
        )
    )

    # Select 10 malicious URLs.
    malicious_samples = (
        df[df["binary_label"] == 1]
        .sample(
            10,
            random_state=RANDOM_STATE
        )
    )

    # Combine both groups.
    selected = pd.concat([
        benign_samples,
        malicious_samples
    ])

    # Create list containing:
    #
    #     (URL, actual label)
    #
    urls = list(
        zip(
            selected["url"],
            selected["binary_label"]
        )
    )

    print("\nURLs selected:", len(urls))

    # ------------------------------------------------------------
    # Run experiment
    # ------------------------------------------------------------

    print("\nRunning adversarial transformations...")

    results = run_experiment(
        model,
        urls
    )

    # ------------------------------------------------------------
    # Save detailed results
    # ------------------------------------------------------------

    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ------------------------------------------------------------
    # Analyze prediction changes
    # ------------------------------------------------------------

    summary = analyze_prediction_changes(
        results
    )

    # Save summary separately.
    summary_file = (
        "data/processed/"
        "adversarial_summary.csv"
    )

    summary.to_csv(
        summary_file,
        index=False
    )

    # ------------------------------------------------------------
    # Display results
    # ------------------------------------------------------------

    print("\n========================================")
    print("ADVERSARIAL TESTING COMPLETE")
    print("========================================")

    print(
        "\nTotal experiments:",
        len(results)
    )

    print(
        "\nDetailed results saved to:"
    )

    print(OUTPUT_FILE)

    print(
        "\nSummary saved to:"
    )

    print(summary_file)

    print(
        "\nPrediction changes by transformation:"
    )

    print(
        summary.to_string(
            index=False
        )
    )


# ================================================================
# Program entry point
# ================================================================

if __name__ == "__main__":
    main()
