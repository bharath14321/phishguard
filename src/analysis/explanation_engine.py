"""
Explainable security decision engine.

Converts risk signals into a human-readable explanation.
"""


def generate_explanation(risk_result):
    """
    Generate a structured explanation from a risk result.
    """

    explanations = []

    for signal in risk_result.signals:

        explanations.append({
            "signal": signal.name,
            "importance": signal.weight,
            "explanation": signal.reason,
            "source": signal.source
        })

    # Highest-weight signals appear first.
    explanations.sort(
        key=lambda item: item["importance"],
        reverse=True
    )

    # Generate a coherent summary aligned with the risk score and signals
    if risk_result.score >= 75:
        summary = "Critical-confidence threat signals detected. Artifact demonstrates active phishing or malicious payload indicators."
    elif risk_result.score >= 50:
        summary = "High-confidence threat signals detected. Artifact demonstrates strong characteristics of malicious phishing or abuse."
    elif risk_result.score >= 25:
        summary = "Suspicious indicators detected requiring further SOC review. Several anomalous attributes were observed during inspection."
    elif len(explanations) > 0:
        summary = "Low-risk scan completed. Informational signals observed without high-risk phishing indicators."
    else:
        summary = "No immediate threat indicators observed. Artifact passed baseline lexical and reputation checks."

    key_reasons = [item["explanation"] for item in explanations[:5]]

    return {
        "risk_score": risk_result.score,
        "risk_level": risk_result.level,
        "summary": summary,
        "key_reasons": key_reasons,
        "explanations": explanations
    }


def print_explanation(explanation):
    """
    Print the explanation in a user-friendly format.
    """

    print("\n" + "=" * 60)
    print("SECURITY EXPLANATION")
    print("=" * 60)

    print(
        f"\nRisk: {explanation['risk_level']}"
    )

    print(
        f"Score: {explanation['risk_score']}/100"
    )

    print("\nWhy:")

    for item in explanation["explanations"]:

        print(
            f"\n[{item['importance']}] "
            f"{item['signal']}"
        )

        print(
            f"  {item['explanation']}"
        )

    print("\n" + "=" * 60)
