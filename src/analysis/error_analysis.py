import pandas as pd

# train_test_split creates the same 80/20 split
# that we used during our baseline experiments.
from sklearn.model_selection import train_test_split

# RandomForestClassifier is our strongest baseline
# according to the current F1 and recall results.
from sklearn.ensemble import RandomForestClassifier


# Location of the feature dataset.
DATA_FILE = "data/processed/url_features.csv"

# File where we will save incorrectly classified URLs.
OUTPUT_FILE = "data/processed/error_analysis.csv"


# These are the exact 14 features used by our models.
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
    "suspicious_keyword_count"
]


def load_dataset():
    """
    Loads the URL feature dataset.

    Returns:
        df -> complete DataFrame
        X  -> 14 ML features
        y  -> binary target
    """

    # Load the complete dataset because we also need
    # the original URL and label for error analysis.
    df = pd.read_csv(DATA_FILE)

    # Extract only the features used by the model.
    X = df[FEATURE_COLUMNS]

    # Extract the binary target.
    # 0 = benign
    # 1 = malicious
    y = df["binary_label"]

    return df, X, y


def split_dataset(X, y):
    """
    Creates the same 80/20 train/test split
    used in our previous experiments.

    Using the same random_state means we can
    compare this analysis with our earlier results.
    """

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train):
    """
    Trains the Random Forest model.

    We use the same basic configuration as our
    previous Random Forest experiment.
    """

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    print("Training Random Forest...")

    # Train the model using only the training data.
    model.fit(X_train, y_train)

    return model


def create_error_table(df, X_test, y_test, model):
    """
    Creates a table containing predictions and identifies
    false positives and false negatives.

    False Positive:
        Actual = benign
        Predicted = malicious

    False Negative:
        Actual = malicious
        Predicted = benign
    """

    # Generate predictions for the unseen test set.
    predictions = model.predict(X_test)

    # Copy the test feature rows so we can safely add
    # prediction-related information.
    results = df.loc[X_test.index].copy()

    # Store the actual label.
    results["actual_label"] = y_test

    # Store the model's prediction.
    results["predicted_label"] = predictions

    # Identify false positives.
    # Actual benign (0), predicted malicious (1).
    results["error_type"] = "correct"

    results.loc[
        (results["actual_label"] == 0) &
        (results["predicted_label"] == 1),
        "error_type"
    ] = "false_positive"

    # Identify false negatives.
    # Actual malicious (1), predicted benign (0).
    results.loc[
        (results["actual_label"] == 1) &
        (results["predicted_label"] == 0),
        "error_type"
    ] = "false_negative"

    # Keep only incorrect predictions.
    errors = results[
        results["error_type"] != "correct"
    ].copy()

    return errors


def main():
    """
    Runs the complete error-analysis pipeline.

    Steps:
        1. Load dataset
        2. Create the same train/test split
        3. Train Random Forest
        4. Generate predictions
        5. Find false positives and false negatives
        6. Save errors to CSV
    """

    print("Loading dataset...")

    # Load complete dataset, features and labels.
    df, X, y = load_dataset()

    print(f"Total samples: {len(df)}")

    # Create the same train/test split used previously.
    X_train, X_test, y_train, y_test = split_dataset(X, y)

    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")

    # Train Random Forest.
    model = train_model(X_train, y_train)

    # Find incorrectly classified URLs.
    errors = create_error_table(
        df,
        X_test,
        y_test,
        model
    )

    # Save the errors so we can investigate them later.
    errors.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n==============================")
    print("ERROR ANALYSIS")
    print("==============================")

    print(f"Total errors: {len(errors)}")

    print("\nError types:")

    print(
        errors["error_type"].value_counts()
    )

    print(f"\nSaved errors to: {OUTPUT_FILE}")


# Run the main function only when this file
# is executed directly.
if __name__ == "__main__":
    main()
