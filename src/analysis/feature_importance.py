import pandas as pd

# Random Forest is used here because it provides
# a built-in feature_importances_ attribute.
from sklearn.ensemble import RandomForestClassifier

# train_test_split creates the same training/testing
# split that we used in our baseline experiments.
from sklearn.model_selection import train_test_split


# Location of the processed feature dataset.
DATA_FILE = "data/processed/url_features.csv"


# These are the features given to the ML model.
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
    Loads the dataset and separates the ML features
    from the binary target label.

    Returns:
        X -> feature matrix
        y -> binary labels
    """

    # Load the CSV file.
    df = pd.read_csv(DATA_FILE)

    # Select only the 14 legitimate ML features.
    X = df[FEATURE_COLUMNS]

    # Select the binary target:
    # 0 = benign
    # 1 = malicious
    y = df["binary_label"]

    return X, y


def train_random_forest(X_train, y_train):
    """
    Creates and trains a Random Forest model.

    The model is trained only on the training data.
    """

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    print("Training Random Forest...")

    # Train the model.
    model.fit(X_train, y_train)

    return model


def show_feature_importance(model):
    """
    Extracts the importance assigned to every feature
    by the trained Random Forest.

    Higher importance means the feature contributed
    more to the model's decision-making.
    """

    # Get the importance value calculated by Random Forest
    # for each feature.
    importance_values = model.feature_importances_

    # Create a table connecting feature names
    # with their importance values.
    importance_df = pd.DataFrame({
        "feature": FEATURE_COLUMNS,
        "importance": importance_values
    })

    # Sort from most important to least important.
    importance_df = importance_df.sort_values(
        by="importance",
        ascending=False
    )

    print("\n==============================")
    print("FEATURE IMPORTANCE")
    print("==============================")

    print(importance_df.to_string(index=False))


def main():
    """
    Runs the complete feature importance analysis.

    Steps:
        1. Load dataset
        2. Split dataset
        3. Train Random Forest
        4. Extract feature importance
    """

    print("Loading dataset...")

    # Load features and labels.
    X, y = load_dataset()

    # Use the same 80/20 split methodology
    # used in our previous experiments.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    # Train the Random Forest model.
    model = train_random_forest(X_train, y_train)

    # Display which features the model considers important.
    show_feature_importance(model)


# Run main() only when this file is executed directly.
if __name__ == "__main__":
    main()
