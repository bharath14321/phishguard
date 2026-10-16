"""
Central artifact analysis service.

This module provides a single entry point for URL analysis.
"""

from src.features.url_analyzer import analyze_url
from src.analysis.risk_engine import analyze_url_risk
from src.analysis.risk_engine import risk_result_to_dict
from src.analysis.explanation_engine import generate_explanation


def analyze_artifact(url):
    """
    Analyze a URL through the complete multi-layer pipeline.

    Pipeline:

        URL
         ↓
        URL intelligence
         ↓
        Domain intelligence
         ↓
        Reputation
         ↓
        Redirect analysis
         ↓
        Webpage analysis
         ↓
        Risk engine
         ↓
        Explanation
    """

    analysis = analyze_url(url)

    risk_result = analyze_url_risk(
        analysis
    )

    risk_data = risk_result_to_dict(
        risk_result
    )

    explanation = generate_explanation(
        risk_result
    )

    return {
        "url_analysis": analysis,
        "risk": risk_data,
        "explanation": explanation
    }


if __name__ == "__main__":

    TEST_URL = "https://example.com"

    result = analyze_artifact(
        TEST_URL
    )

    print("\nRisk:")
    print(result["risk"])

    print("\nExplanation:")
    print(result["explanation"])
