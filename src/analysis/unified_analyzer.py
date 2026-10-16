import uuid
import json
import os
import hashlib
import tempfile
from pathlib import Path
from typing import List, Dict, Any

from src.features.url_analyzer import analyze_url as url_analyzer
from src.features.reputation import get_hash_reputation, get_url_reputation, normalize_vt_result
from src.features.local_ti import query_local_threat_intelligence, aggregate_local_ti_results
from src.features.tracking_pixel_detector import detect_tracking_pixels
from src.features.tls_analyzer import analyze_tls_certificate
from src.features.domain_intelligence import analyze_domain
from src.models.url_model_inference import predict_url
from src.features.email_analyzer import (
    analyze_email as email_analyzer,
    parse_email_file,
    analyze_email_headers,
    extract_email_body,
)
from src.features.email_authentication import analyze_email_authentication
from src.features.email_nlp import analyze_email_subject_and_body
from src.features.email_url_extractor import analyze_email_urls
from src.features.attachment_analyzer import analyze_attachment
from src.features.attachment_url_extractor import extract_embedded_urls
from src.features.qr_analyzer import analyze_qr_code as qr_analyzer
from src.features.email_qr_extractor import extract_qr_from_email

from src.analysis.risk_engine import analyze_url_risk, clamp_score, determine_risk_level, RiskSignal
from src.analysis.explanation_engine import generate_explanation
from src.analysis.evidence_correlator import correlate_evidence
from src.analysis.model_explainer import explain_url_model
from src.analysis.multi_layer_risk import aggregate_multi_layer_risk
# Helper to generate grounded AI assessment
def _generate_ai_assessment(context_dict: Dict[str, Any]) -> Dict[str, Any]:
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        return {
            "status": "UNCONFIGURED",
            "message": "Google Gemini API key not configured. Set GEMINI_API_KEY in backend environment to enable generative AI security analysis.",
            "provider": "security_analyst",
            "evaluation": None,
        }
    try:
        from src.analysis.security_chat import process_chat_message
        chat_res = process_chat_message(
            "Provide an executive security assessment and key findings for this artifact.",
            analysis_context=context_dict,
        )
        return {
            "status": "READY",
            "message": "AI Security Analyst evaluation generated.",
            "provider": chat_res.get("provider", "gemini"),
            "evaluation": chat_res.get("response", ""),
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"AI Analyst generation failed: {str(exc)}",
            "provider": "security_analyst",
            "evaluation": None,
        }

# Helper to compute SHA256 of a file
def _sha256_file(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# Standard response builder
# Standard response builder
def _build_response(
    analysis_id: Any,
    artifact_type: str,
    details: Dict[str, Any],
    risk_result: Any,
    explanation: Dict[str, Any],
    errors: List[str] = None,
) -> Dict[str, Any]:
    if errors is None:
        errors = []
    raw_score = getattr(risk_result, "score", 0.0)
    canonical_score = float(clamp_score(raw_score))
    canonical_level = determine_risk_level(canonical_score)
    signals_list = getattr(risk_result, "signals", [])
    
    # Ensure details persists structured signals for database serialization
    formatted_signals = []
    for s in signals_list:
        if hasattr(s, "to_dict"):
            formatted_signals.append(s.to_dict())
        elif isinstance(s, dict):
            name = s.get("name") or s.get("signal") or "Signal"
            reason = s.get("reason") or s.get("explanation") or s.get("description") or ""
            weight = float(s.get("weight", s.get("importance", 0)))
            source = s.get("source", "core_engine")
            severity = s.get("severity") or ("CRITICAL" if weight >= 75 else "HIGH" if weight >= 40 else "MEDIUM" if weight >= 20 else "LOW")
            formatted_signals.append({
                "name": name,
                "weight": weight,
                "reason": reason,
                "source": source,
                "finding": name,
                "explanation": reason,
                "severity": severity,
            })
        else:
            str_s = str(s)
            formatted_signals.append({
                "name": str_s,
                "weight": 0.0,
                "reason": str_s,
                "source": "core_engine",
                "finding": str_s,
                "explanation": str_s,
                "severity": "LOW",
            })

    if details is not None and isinstance(details, dict):
        details["signals"] = formatted_signals

    resp = {
        "analysis_id": analysis_id,
        "artifact_type": artifact_type,
        "risk": {
            "score": canonical_score,
            "level": canonical_level,
        },
        "risk_score": canonical_score,
        "risk_level": canonical_level,
        "summary": explanation.get("summary", ""),
        "signals": formatted_signals,
        "details": details,
        "explanation": explanation,
        "errors": errors,
    }

    return resp

def analyze_url(url: str, user_id: int) -> Dict[str, Any]:
    """Analyze a URL using deterministic logic, local threat intelligence, and optional ML inference.

    Decision flow:
    1. Local Threat Intelligence lookup (PhishTank, URLhaus, OpenPhish)
    2. Deterministic multi-layer feature extraction & heuristics (without eager VT call)
    3. Machine Learning inference prediction
    4. Evidence Sufficiency & conditional VirusTotal escalation
    5. Unified risk aggregation & grounded AI analyst evaluation
    """
    from src.features.reputation import normalize_vt_result
    errors = []
    
    # 1. Local Threat Intelligence Check first
    try:
        local_ti = query_local_threat_intelligence(url, "url")
    except Exception as exc:
        local_ti = {"found": False, "status": "UNKNOWN", "error": str(exc)}

    # 2. Deterministic feature extraction (pass check_vt=False so VT is conditional)
    try:
        url_details = url_analyzer(url, check_vt=False)
    except Exception as exc:
        url_details = {}
        errors.append(str(exc))

    url_details["local_ti"] = local_ti

    # 3. Supervised Machine Learning inference – evaluated before risk engine calculation
    try:
        from src.models.url_model_inference import predict_url
        ml_result = predict_url(url)
    except Exception:
        ml_result = {"model_available": False, "probability": None, "features": {}}

    url_details["ml"] = ml_result

    # 4. Base risk calculation from deterministic features and ML assessment
    risk_res = analyze_url_risk(url_details)

    # 5. Apply Local Threat Intelligence or Conditional VirusTotal Escalation
    has_vt_key = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
    should_vt = False
    vt_reason = "Not evaluated"

    if local_ti.get("found"):
        ti_signal = RiskSignal(
            name="Local Threat Intelligence Match",
            weight=85.0,
            reason=f"Known malicious indicator matched in local {local_ti.get('source')} threat feed.",
            source="local_threat_intelligence",
        )
        risk_res.signals.append(ti_signal)
        risk_res.score = max(risk_res.score, 85.0)
        risk_res.level = determine_risk_level(risk_res.score)
        url_details["virustotal"] = normalize_vt_result({
            "status": "NOT_REQUIRED",
            "source": "virustotal",
            "provider": "VirusTotal",
            "malicious": 0,
            "total": 0,
            "message": f"Local threat intelligence match confirmed ({local_ti.get('source')}); external lookup skipped.",
        }, url)
    else:
        # Check conditional VT escalation
        try:
            from src.analysis.evidence_sufficiency import should_query_virustotal
            interim_data = {"details": url_details, "risk": {"score": risk_res.score}, "local_ti": local_ti}
            should_vt, vt_reason = should_query_virustotal(interim_data, has_api_key=has_vt_key)
        except Exception:
            should_vt = False
            vt_reason = "Evidence sufficiency check skipped"

        if should_vt and has_vt_key:
            try:
                vt_raw = get_url_reputation(url)
                url_details["virustotal"] = normalize_vt_result(vt_raw, url)
                mal_count = url_details["virustotal"].get("malicious", 0)
                if mal_count > 0:
                    vt_signal = RiskSignal(
                        name="Threat Intelligence Detection",
                        weight=min(25.0, 10.0 + float(mal_count)),
                        reason=f"Threat intelligence reported {mal_count} malicious detections across {url_details['virustotal'].get('total', 70)} vendors.",
                        source="virustotal",
                    )
                    risk_res.signals.append(vt_signal)
                    risk_res.score = max(risk_res.score, 80.0)
                    risk_res.level = determine_risk_level(risk_res.score)
            except Exception as vt_exc:
                url_details["virustotal"] = normalize_vt_result({
                    "status": "ERROR",
                    "error": str(vt_exc),
                    "message": f"VirusTotal lookup failed: {vt_exc}",
                }, url)
        elif not has_vt_key:
            url_details["virustotal"] = normalize_vt_result({
                "status": "UNAVAILABLE",
                "message": "Threat intelligence service unavailable (API key not configured).",
            }, url)
        else:
            url_details["virustotal"] = normalize_vt_result({
                "status": "NOT_REQUIRED",
                "message": "High evidence sufficiency achieved; external lookup not required.",
            }, url)

    explanation = generate_explanation(risk_res)

    # 6. Build base response
    response = _build_response(
        analysis_id=None,
        artifact_type="url",
        details=url_details,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )

    response["ml"] = ml_result
    response["local_ti"] = local_ti
    response["virustotal"] = url_details.get("virustotal")
    response["url"] = url
    try:
        response["model_explanation"] = explain_url_model(url)
    except Exception:
        response["model_explanation"] = None

    # Evidence correlation
    try:
        corr_input = {"url_details": url_details, "ml": ml_result}
        response["evidence_correlation"] = correlate_evidence(corr_input)
    except Exception:
        response["evidence_correlation"] = None

    # Multi-layer risk aggregation
    response["multi_layer_risk"] = aggregate_multi_layer_risk({
        "ml": response.get("ml"),
        "url_details": url_details,
        "final_risk": risk_res,
        "correlated_evidence": response.get("evidence_correlation"),
        "explanation": explanation,
    })

    # 7. Evidence Sufficiency & Independent Class Evaluation
    try:
        from src.analysis.evidence_sufficiency import compute_evidence_sufficiency
        suff = compute_evidence_sufficiency(response)
        suff_dict = {
            "score": suff.score,
            "level": suff.level.value,
            "evidence_classes": suff.evidence_classes_present,
            "signals_count": suff.signals_count,
            "has_contradiction": suff.has_contradiction,
            "contradictions": suff.contradictions,
            "vt_escalation": {
                "should_query": should_vt,
                "reason": vt_reason,
            }
        }
        response["evidence_sufficiency"] = suff_dict
        url_details["evidence_sufficiency"] = suff_dict
    except Exception as exc:
        suff_dict = {
            "score": 0.0,
            "level": "INSUFFICIENT",
            "evidence_classes": [],
            "error": str(exc)
        }
        response["evidence_sufficiency"] = suff_dict
        url_details["evidence_sufficiency"] = suff_dict

    # 8. Grounded AI Security Analyst Assessment with full telemetry
    ai_eval = _generate_ai_assessment(response)
    response["ai_analyst"] = ai_eval
    url_details["ai_analyst"] = ai_eval

    return response

def analyze_hash(hash_value: str, user_id: int) -> Dict[str, Any]:
    """Analyze a file hash against Local Threat Intelligence and external VirusTotal reputation."""
    errors = []
    clean_hash = hash_value.strip().lower()
    # Accept MD5 (32), SHA1 (40), SHA256 (64) hex strings
    if not all(c in "0123456789abcdef" for c in clean_hash) or len(clean_hash) not in {32, 40, 64}:
        errors.append("Invalid hash format")
        dummy_res = type("obj", (), {"score": 0.0, "level": "UNKNOWN", "signals": []})()
        dummy_exp = {"summary": "Invalid hash format provided.", "key_reasons": []}
        return _build_response(
            analysis_id=None,
            artifact_type="hash",
            details={"hash": hash_value},
            risk_result=dummy_res,
            explanation=dummy_exp,
            errors=errors,
        )

    # 1. Check Local Threat Intelligence first
    local_ti = query_local_threat_intelligence(clean_hash, "hash")
    signals = []

    if local_ti.get("found"):
        score = 90.0
        level = determine_risk_level(score)
        signals.append({
            "name": "Local Threat Intelligence Match",
            "weight": 90.0,
            "reason": f"Known malicious file hash matched in local {local_ti.get('source')} feed.",
            "source": "local_threat_intelligence",
        })
        vt_rep = normalize_vt_result({
            "status": "NOT_QUERIED",
            "source": "virustotal",
            "provider": "VirusTotal",
            "malicious": 0,
            "total": 0,
            "message": f"NOT_QUERIED — skipped by policy (confirmed match in local {local_ti.get('source')} threat intelligence).",
            "policy_reason": "SKIPPED_BY_POLICY_LOCAL_MATCH",
        }, clean_hash)
        reputation = {
            "hash": clean_hash,
            "local_ti": local_ti,
            "malicious": True,
            "status": "FOUND",
            "source": local_ti.get("source"),
            "virustotal": vt_rep,
        }
        explanation = {
            "summary": f"Known malware file hash confirmed by local threat intelligence ({local_ti.get('source')}).",
            "key_reasons": [f"Matched {local_ti.get('source')} threat indicator database"],
        }
    else:
        # 2. Check External VirusTotal reputation if configured
        has_vt_key = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
        if has_vt_key:
            vt_rep_raw = get_hash_reputation(clean_hash)
            vt_rep = normalize_vt_result(vt_rep_raw, clean_hash)
        else:
            vt_rep = normalize_vt_result({
                "status": "UNAVAILABLE",
                "message": "VirusTotal API key not configured.",
            }, clean_hash)

        mal_count = vt_rep.get("malicious", 0)
        susp_count = vt_rep.get("suspicious", 0)
        malicious = mal_count > 0
        suspicious = susp_count > 0

        if malicious:
            score = 85.0
            signals.append({
                "name": "VirusTotal Malicious Reputation",
                "weight": 85.0,
                "reason": f"VirusTotal flagged hash as malicious ({mal_count} engines).",
                "source": "virustotal",
            })
        elif suspicious:
            score = 45.0
            signals.append({
                "name": "VirusTotal Suspicious Reputation",
                "weight": 45.0,
                "reason": f"VirusTotal engines returned {susp_count} suspicious detections.",
                "source": "virustotal",
            })
        else:
            score = 0.0

        level = determine_risk_level(score)
        reputation = {
            "hash": clean_hash,
            "local_ti": local_ti,
            "virustotal": vt_rep,
            "threat_label": vt_rep.get("threat_label", "Unknown / not provided"),
            "threat_category": vt_rep.get("threat_category", "Unknown"),
            "threat_family": vt_rep.get("threat_family", "Unknown"),
            "malicious": bool(malicious),
            "suspicious": bool(suspicious),
        }
        if malicious or suspicious:
            explanation = {
                "summary": f"Hash flagged by VirusTotal threat intelligence ({level} risk).",
                "key_reasons": [f"Detections reported by external reputation engines"],
            }
        else:
            explanation = {
                "summary": "No malicious reputation observed across local feeds or external intelligence.",
                "key_reasons": ["Clean / unobserved hash"],
            }

    ml_not_applicable = {
        "model_available": False,
        "status": "NOT_APPLICABLE",
        "message": "ML URL classifier: Not applicable to this artifact type",
        "probability": None,
        "features": {},
    }
    reputation["ml"] = ml_not_applicable

    risk_res = type("obj", (), {"score": score, "level": level, "signals": signals})()
    response = _build_response(
        analysis_id=None,
        artifact_type="hash",
        details=reputation,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )
    response["ml"] = ml_not_applicable
    response["local_ti"] = local_ti
    response["virustotal"] = vt_rep

    try:
        from src.analysis.evidence_sufficiency import compute_evidence_sufficiency
        suff = compute_evidence_sufficiency(response)
        suff_dict = {
            "score": suff.score,
            "level": suff.level.value,
            "evidence_classes": suff.evidence_classes_present,
            "signals_count": suff.signals_count,
            "has_contradiction": suff.has_contradiction,
            "contradictions": suff.contradictions,
        }
        response["evidence_sufficiency"] = suff_dict
        reputation["evidence_sufficiency"] = suff_dict
    except Exception as exc:
        suff_dict = {
            "score": 0.0,
            "level": "INSUFFICIENT",
            "evidence_classes": [],
            "error": str(exc),
        }
        response["evidence_sufficiency"] = suff_dict
        reputation["evidence_sufficiency"] = suff_dict

    ai_eval = _generate_ai_assessment(response)
    response["ai_analyst"] = ai_eval
    reputation["ai_analyst"] = ai_eval

    return response

def analyze_email(file_path: str, user_id: int = 1) -> Dict[str, Any]:
    """Analyze an email deterministically and augment with multi-layer detection:
    - Email header & identity analysis (From, Reply-To, display name mismatch)
    - Email authentication parsing (SPF, DKIM, DMARC message auth & published DNS policy)
    - Email NLP / social engineering analysis (urgency, credential harvesting, call-to-actions)
    - Body URL extraction & analysis (plain-text, HTML, visible link vs href mismatch)
    - Attachment extraction, static analysis & embedded URL fan-out to central URL analyzer
    - Embedded QR code decoding and URL routing
    - Multi-layer evidence correlation, evidence sufficiency, and risk calculation
    """
    errors = []

    # 1. Parse email structure, headers, and body
    try:
        msg = parse_email_file(file_path)
        headers = analyze_email_headers(msg)
        body = extract_email_body(msg)
        email_data = {"headers": headers, "body": body}
    except Exception as exc:
        msg = None
        headers = {}
        body = {"plain_text": "", "html": ""}
        email_data = {"headers": headers, "body": body}
        errors.append(f"Email parsing error: {exc}")

    # 2. Email Authentication (SPF, DKIM, DMARC from Authentication-Results + DNS Policy)
    try:
        if msg is not None:
            auth_results = analyze_email_authentication(msg)
        else:
            auth_results = {
                "authentication_headers": [],
                "message_authentication": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
                "status": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
                "published_dns_policy": {"published_spf": "unknown", "published_dmarc": "unknown", "dns_lookup_success": False},
                "signals": {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False, "spf_fail": False, "dkim_fail": False, "dmarc_fail": False},
            }
    except Exception as exc:
        auth_results = {
            "authentication_headers": [],
            "message_authentication": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
            "status": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
            "published_dns_policy": {"published_spf": "unknown", "published_dmarc": "unknown", "dns_lookup_success": False},
            "signals": {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False, "spf_fail": False, "dkim_fail": False, "dmarc_fail": False},
        }
        errors.append(f"Email authentication analysis error: {exc}")

    # 3. Email NLP (Urgency, Credential Theft, Actions)
    try:
        subject = headers.get("subject", "")
        combined_body = (body.get("plain_text", "") + " " + body.get("html", "")).strip()
        nlp_results = analyze_email_subject_and_body(subject, combined_body)
    except Exception as exc:
        nlp_results = {}
        errors.append(f"Email NLP analysis error: {exc}")

    # 4. Extract and analyze URLs from plain text and HTML body
    url_results = []
    try:
        raw_urls = analyze_email_urls(body.get("plain_text", ""), body.get("html", ""))
        for u_item in raw_urls:
            u_str = u_item.get("url")
            if not u_str:
                continue
            try:
                u_analysis = url_analyzer(u_str, check_vt=False)
                u_local_ti = query_local_threat_intelligence(u_str, "url")
                u_analysis["local_ti"] = u_local_ti
                
                # Independent Machine Learning inference on child URL
                try:
                    u_ml = predict_url(u_str)
                except Exception:
                    u_ml = {"model_available": False, "probability": None, "features": {}}
                u_analysis["ml"] = u_ml

                # Passive TLS certificate inspection for HTTPS destinations
                try:
                    u_tls = analyze_tls_certificate(u_str)
                except Exception as tls_exc:
                    u_tls = {
                        "status": "UNAVAILABLE",
                        "is_https": u_str.lower().startswith("https://"),
                        "error": str(tls_exc),
                    }
                u_analysis["tls"] = u_tls

                # Compute URL risk with ML, Local TI, and Webpage attached
                u_risk = analyze_url_risk(u_analysis)
                u_score = float(getattr(u_risk, "score", 0.0))
                if u_local_ti.get("found"):
                    u_score = max(u_score, 85.0)
                u_level = determine_risk_level(u_score)
                
                u_dom_intel = u_analysis.get("domain_intelligence") or {}
                reg_dom = u_dom_intel.get("registrable_domain") or u_dom_intel.get("hostname") or ""

                u_signals = [s.to_dict() if hasattr(s, "to_dict") else s for s in getattr(u_risk, "signals", [])]

                u_item["url_analysis"] = u_analysis
                u_item["local_ti"] = u_local_ti
                u_item["ml"] = u_ml
                u_item["tls"] = u_tls
                u_item["domain"] = reg_dom
                u_item["domain_intelligence"] = u_dom_intel
                u_item["redirects"] = u_analysis.get("redirect_analysis") or {}
                u_item["redirect_analysis"] = u_analysis.get("redirect_analysis") or {}
                u_item["webpage_analysis"] = u_analysis.get("webpage_analysis") or {}
                u_item["risk"] = {
                    "score": u_score,
                    "level": u_level,
                    "signals": u_signals,
                }
            except Exception as u_exc:
                u_item["error"] = str(u_exc)
                u_item["risk"] = {"score": 0.0, "level": "UNKNOWN", "signals": []}
            url_results.append(u_item)
    except Exception as exc:
        errors.append(f"Email URL extraction error: {exc}")

    # 5. Extract and statically analyze attachments + embedded URL fan-out
    attachments = []
    attachment_url_results = []
    if msg is not None:
        try:
            with tempfile.TemporaryDirectory(prefix="phishguard_att_") as tmpdir:
                for i, part in enumerate(msg.walk()):
                    disposition = part.get_content_disposition()
                    filename = part.get_filename()
                    content_id = (part.get("Content-ID") or "").strip("<>")
                    is_inline = (disposition == "inline")

                    # Identify attachment parts while preserving inline image metadata
                    is_att = bool(
                        disposition == "attachment"
                        or filename
                        or (is_inline and not part.get_content_type().startswith("text/") and not part.is_multipart())
                    )

                    if is_att:
                        fn = filename or f"attachment_{i}.bin"
                        content = part.get_payload(decode=True)
                        if content is None:
                            try:
                                raw_payload = part.get_content()
                                if isinstance(raw_payload, str):
                                    content = raw_payload.encode("utf-8", errors="replace")
                                elif isinstance(raw_payload, bytes):
                                    content = raw_payload
                            except Exception:
                                content = b""
                        if content is None:
                            content = b""

                        tmp_path = Path(tmpdir) / fn
                        tmp_path.write_bytes(content)

                        static_info = analyze_attachment(str(tmp_path))
                        emb_urls = extract_embedded_urls(str(tmp_path))
                        mime_type = part.get_content_type() or static_info.get("mime_type") or "application/octet-stream"
                        ext = static_info.get("extension") or Path(fn).suffix.lower()

                        macro_stat = static_info.get("macro_status") or ("MACROS_DETECTED" if static_info.get("has_vba_macros") or static_info.get("macro_enabled") else "NO_MACROS_FOUND")
                        macro_det = static_info.get("macro_details") or ("VBA macros detected" if static_info.get("macro_enabled") else "No macros found")

                        attachments.append({
                            "filename": fn,
                            "size_bytes": len(content),
                            "mime_type": mime_type,
                            "detected_type": mime_type,
                            "extension": ext,
                            "sha256": static_info.get("sha256"),
                            "is_inline": is_inline,
                            "content_id": content_id,
                            "disposition": disposition or ("inline" if is_inline else "attachment"),
                            "static_analysis": static_info,
                            "embedded_urls": emb_urls,
                            "has_vba_macros": static_info.get("has_vba_macros", static_info.get("macro_enabled", False)),
                            "macro_status": macro_stat,
                            "macro_details": macro_det,
                        })

                        # Attachment URL fan-out to central URL analyzer & Local TI
                        for u in emb_urls:
                            try:
                                u_analysis = url_analyzer(u, check_vt=False)
                                u_local_ti = query_local_threat_intelligence(u, "url")
                                u_analysis["local_ti"] = u_local_ti

                                try:
                                    u_ml = predict_url(u)
                                except Exception:
                                    u_ml = {"model_available": False, "probability": None, "features": {}}
                                u_analysis["ml"] = u_ml

                                try:
                                    u_tls = analyze_tls_certificate(u)
                                except Exception as tls_exc:
                                    u_tls = {
                                        "status": "UNAVAILABLE",
                                        "is_https": u.lower().startswith("https://"),
                                        "error": str(tls_exc),
                                    }
                                u_analysis["tls"] = u_tls

                                # Compute URL risk with ML, Local TI, and Webpage attached
                                u_risk = analyze_url_risk(u_analysis)
                                u_score = float(getattr(u_risk, "score", 0.0))
                                if u_local_ti.get("found"):
                                    u_score = max(u_score, 85.0)
                                u_level = determine_risk_level(u_score)

                                u_dom_intel = u_analysis.get("domain_intelligence") or {}
                                reg_dom = u_dom_intel.get("registrable_domain") or u_dom_intel.get("hostname") or ""

                                u_signals = [s.to_dict() if hasattr(s, "to_dict") else s for s in getattr(u_risk, "signals", [])]

                                attachment_url_results.append({
                                    "url": u,
                                    "source": f"attachment:{fn}",
                                    "visible_text": None,
                                    "domain_mismatch": False,
                                    "url_analysis": u_analysis,
                                    "local_ti": u_local_ti,
                                    "ml": u_ml,
                                    "tls": u_tls,
                                    "domain": reg_dom,
                                    "domain_intelligence": u_dom_intel,
                                    "redirects": u_analysis.get("redirect_analysis") or {},
                                    "redirect_analysis": u_analysis.get("redirect_analysis") or {},
                                    "webpage_analysis": u_analysis.get("webpage_analysis") or {},
                                    "risk": {
                                        "score": u_score,
                                        "level": u_level,
                                        "signals": u_signals,
                                    },
                                })
                            except Exception as u_exc:
                                attachment_url_results.append({
                                    "url": u,
                                    "source": f"attachment:{fn}",
                                    "error": str(u_exc),
                                    "risk": {"score": 0.0, "level": "UNKNOWN", "signals": []},
                                })
                                errors.append(f"Attachment URL analysis error for {u}: {u_exc}")
        except Exception as exc:
            errors.append(f"Attachment extraction error: {exc}")

    # 6. Embedded QR code extraction and analysis from image MIME parts
    try:
        qr_analysis = extract_qr_from_email(file_path)
    except Exception as exc:
        qr_analysis = {
            "detected": False,
            "image_count": 0,
            "qr_count": 0,
            "findings": [],
            "errors": [str(exc)],
        }
        errors.append(f"Email QR inspection error: {exc}")

    qr_findings = qr_analysis.get("findings", [])
    qr_url_results = []
    for f in qr_findings:
        if f.get("is_url") and f.get("url_analysis"):
            risk_dict = f.get("url_risk") or {}
            decoded_u = f.get("decoded_data")
            qr_local_ti = query_local_threat_intelligence(decoded_u, "url") if decoded_u else {"found": False}
            qr_score = float(risk_dict.get("score", 0.0))
            if qr_local_ti.get("found"):
                qr_score = max(qr_score, 85.0)
            qr_level = determine_risk_level(qr_score)
            qr_url_results.append({
                "url": decoded_u,
                "source": "embedded_qr",
                "source_part": f.get("source_part"),
                "visible_text": None,
                "domain_mismatch": False,
                "analysis": f.get("url_analysis"),
                "url_analysis": f.get("url_analysis"),
                "local_ti": qr_local_ti,
                "risk": {
                    "score": qr_score,
                    "level": qr_level,
                },
            })

    # 6B. HTML Image Resource & Tracking-Pixel Detection
    try:
        tracking_analysis = detect_tracking_pixels(
            html_content=body.get("html", ""),
            mime_image_count=qr_analysis.get("image_count", 0),
        )
    except Exception as exc:
        tracking_analysis = {
            "detected": False,
            "status": "NOT_DETECTED",
            "html_image_resources_count": 0,
            "mime_image_count": qr_analysis.get("image_count", 0),
            "tracking_pixels_count": 0,
            "resources": [],
            "suspected_tracking_pixels": [],
            "reasons": [str(exc)],
        }
        errors.append(f"Tracking pixel detection error: {exc}")

    # 6C. Sender Domain Intelligence & TLS Check
    from_email = headers.get("from_email", "")
    from_domain = from_email.split("@")[-1] if "@" in from_email else ""
    sender_domain_intel = None
    if from_domain:
        try:
            sender_domain_intel = analyze_domain(from_domain, check_tls=True)
        except Exception as d_exc:
            sender_domain_intel = {"domain": from_domain, "error": str(d_exc)}

    # 7. Collect Multi-Layer Risk Signals
    signals = []
    accumulated_score = 0.0

    # (a) Sender Identity Signals
    display_analysis = headers.get("display_name_analysis", {})
    display_mismatch = display_analysis.get("possible_mismatch", False)
    reply_mismatch = headers.get("reply_to_domain_mismatch", False)
    if display_mismatch and reply_mismatch:
        signals.append({
            "name": "Sender Identity Deception",
            "reason": "Both display-name brand and Reply-To domain mismatch the sender From domain.",
            "weight": 25,
            "source": "email_headers",
        })
        accumulated_score += 25
    elif display_mismatch:
        signals.append({
            "name": "Display Name Brand Mismatch",
            "reason": "Display name indicates a recognized brand that differs from the From domain.",
            "weight": 15,
            "source": "email_headers",
        })
        accumulated_score += 15
    elif reply_mismatch:
        signals.append({
            "name": "Reply-To Domain Mismatch",
            "reason": "Reply-To address domain differs from From address domain.",
            "weight": 15,
            "source": "email_headers",
        })
        accumulated_score += 15

    # (b) Email Authentication Failure Signals
    auth_signals = auth_results.get("signals", {})
    auth_status = auth_results.get("message_authentication", {})
    auth_fail_count = sum(1 for k in ("spf_fail", "dkim_fail", "dmarc_fail") if auth_signals.get(k))
    if auth_fail_count >= 2:
        signals.append({
            "name": "Multiple Email Authentication Failures",
            "reason": f"Email failed multiple authentication checks (SPF={auth_status.get('spf')}, DKIM={auth_status.get('dkim')}, DMARC={auth_status.get('dmarc')}).",
            "weight": 20,
            "source": "email_authentication",
        })
        accumulated_score += 20
    elif auth_fail_count == 1:
        signals.append({
            "name": "Email Authentication Failure",
            "reason": f"Email failed an authentication check (SPF={auth_status.get('spf')}, DKIM={auth_status.get('dkim')}, DMARC={auth_status.get('dmarc')}).",
            "weight": 10,
            "source": "email_authentication",
        })
        accumulated_score += 10

    # (c) NLP Urgency & Credential Theft Signals
    urgency_cnt = nlp_results.get("urgency_count", 0)
    credential_cnt = nlp_results.get("credential_count", 0)
    if urgency_cnt >= 2:
        signals.append({
            "name": "High Urgency Psychological Coercion",
            "reason": f"Email body and subject contain {urgency_cnt} high-urgency pressure indicators.",
            "weight": 15,
            "source": "email_nlp",
        })
        accumulated_score += 15
    elif urgency_cnt == 1:
        signals.append({
            "name": "Urgency Indicator",
            "reason": "Email body contains urgency language.",
            "weight": 5,
            "source": "email_nlp",
        })
        accumulated_score += 5

    if credential_cnt >= 1:
        signals.append({
            "name": "Credential Request Language",
            "reason": f"Email requests account verification or credentials ({credential_cnt} matches).",
            "weight": 15,
            "source": "email_nlp",
        })
        accumulated_score += 15

    # (d) URL Signals (Body & Attachments & QR)
    for u_item in url_results:
        if u_item.get("domain_mismatch"):
            signals.append({
                "name": "Visible Text vs Destination URL Mismatch",
                "reason": f"HTML link text '{u_item.get('visible_text')}' misleadingly points to '{u_item.get('url')}'.",
                "weight": 20,
                "source": "email_url_extractor",
            })
            accumulated_score += 20

        ti = u_item.get("local_ti", {})
        u_score_val = u_item.get("risk", {}).get("score", 0)
        webpage_info = u_item.get("webpage_analysis") or {}
        u_ml = u_item.get("ml") or {}

        if ti.get("found"):
            signals.append({
                "name": f"Malicious URL in Email Body ({ti.get('source', 'Local TI')})",
                "reason": f"Destination URL '{u_item.get('url')}' matched local threat feed '{ti.get('source')}' as malicious ({ti.get('threat_type') or 'phishing'}).",
                "weight": 85,
                "source": "local_threat_intelligence",
            })
            accumulated_score = max(accumulated_score, 85.0)
        elif u_score_val >= 50:
            signals.append({
                "name": "High-Risk Destination URL in Body",
                "reason": f"URL '{u_item.get('url')}' exhibits suspicious phishing characteristics (score {u_score_val}).",
                "weight": 35,
                "source": "url_risk_engine",
            })
            accumulated_score = max(accumulated_score, u_score_val)
        else:
            # Capture specific structural webpage signals from child URL
            if webpage_info.get("has_cross_domain_submission") or webpage_info.get("cross_domain_forms"):
                signals.append({
                    "name": "Destination URL Submits Credentials Across Domains",
                    "reason": f"Webpage at '{u_item.get('url')}' targets external cross-domain endpoints for form actions.",
                    "weight": 25,
                    "source": "webpage_analyzer",
                })
                accumulated_score += 25
            elif webpage_info.get("has_password_field") or webpage_info.get("password_field_count", 0) > 0:
                signals.append({
                    "name": "Destination URL Collects Credentials",
                    "reason": f"Webpage at '{u_item.get('url')}' contains password input fields.",
                    "weight": 10,
                    "source": "webpage_analyzer",
                })
                accumulated_score += 10

            # Independent lexical ML signal when not already flagged by threat intel
            p_val = u_ml.get("phishing_probability") if u_ml.get("phishing_probability") is not None else u_ml.get("probability")
            if p_val is not None and p_val >= 0.8:
                signals.append({
                    "name": "Machine Learning URL Phishing Suspicion",
                    "reason": f"URL classifier flagged '{u_item.get('url')}' with {p_val:.1%} phishing probability (lexical heuristic).",
                    "weight": 20,
                    "source": "url_model_inference",
                })

    for att_u in attachment_url_results:
        ti = att_u.get("local_ti", {})
        att_u_score = att_u.get("risk", {}).get("score", 0)
        if ti.get("found"):
            signals.append({
                "name": f"Malicious URL in Attachment ({ti.get('source', 'Local TI')})",
                "reason": f"URL '{att_u.get('url')}' in attachment matched local threat feed '{ti.get('source')}'.",
                "weight": 85,
                "source": "local_threat_intelligence",
            })
            accumulated_score = max(accumulated_score, 85.0)
        elif att_u_score >= 50:
            signals.append({
                "name": "High-Risk Destination URL in Attachment",
                "reason": f"URL '{att_u.get('url')}' in attachment exhibits high risk (score {att_u_score}).",
                "weight": 35,
                "source": "url_risk_engine",
            })
            accumulated_score = max(accumulated_score, att_u_score)

    for qr_u in qr_url_results:
        ti = qr_u.get("local_ti", {})
        qr_u_score = qr_u.get("risk", {}).get("score", 0)
        if ti.get("found"):
            signals.append({
                "name": f"Malicious URL in QR Code ({ti.get('source', 'Local TI')})",
                "reason": f"QR code URL '{qr_u.get('url')}' matched local threat feed '{ti.get('source')}'.",
                "weight": 85,
                "source": "local_threat_intelligence",
            })
            accumulated_score = max(accumulated_score, 85.0)
        elif qr_u_score >= 50:
            signals.append({
                "name": "High-Risk QR Destination URL",
                "reason": f"QR code URL '{qr_u.get('url')}' exhibits high risk (score {qr_u_score}).",
                "weight": 35,
                "source": "url_risk_engine",
            })
            accumulated_score = max(accumulated_score, qr_u_score)

    # Collect individual URL risk scores
    all_extracted_url_results = url_results + attachment_url_results + qr_url_results
    url_scores = []
    for r in all_extracted_url_results:
        risk_obj = r.get("risk") or {}
        score_val = risk_obj.get("score", 0)
        url_scores.append(score_val)

    if url_scores and max(url_scores) > 0:
        max_u_score = max(url_scores)
        accumulated_score = max(accumulated_score, max_u_score)

    # (e) QR Code Signals
    if qr_analysis.get("detected"):
        qr_count = qr_analysis.get("qr_count", 0)
        signals.append({
            "name": "Embedded QR Code Detected",
            "reason": f"Email contains {qr_count} embedded QR code(s) with decoded payload.",
            "weight": 10,
            "source": "qr_analysis",
            "severity": "HIGH" if max(url_scores, default=0) > 0 else "MEDIUM",
        })
        accumulated_score += 10

    # (f) Attachment Signals
    for att in attachments:
        static = att.get("static_analysis", {})
        if static.get("macro_enabled"):
            signals.append({
                "name": "Macro-Enabled Attachment",
                "reason": f"Attachment '{att.get('filename')}' contains VBA macros.",
                "weight": 25,
                "source": "attachment_analyzer",
            })
            accumulated_score += 25
        if static.get("suspicious_extension"):
            signals.append({
                "name": "Suspicious Executable Extension",
                "reason": f"Attachment '{att.get('filename')}' has an executable or dangerous extension.",
                "weight": 25,
                "source": "attachment_analyzer",
            })
            accumulated_score += 25

    # (g) HTML Resource / Tracking Pixel Signals
    if tracking_analysis.get("detected"):
        tracking_reason = tracking_analysis["reasons"][0] if tracking_analysis.get("reasons") else "Remote 1×1 image detected consistent with an email tracking pixel."
        # If there are other threat signals present, tracking pixel contributes supporting context (weight 5);
        # otherwise it is purely informational (weight 0) to avoid false-positive flagging on ordinary benign emails
        pixel_weight = 5 if accumulated_score > 0 else 0
        signals.append({
            "name": "Email Tracking Pixel Suspected",
            "reason": tracking_reason,
            "weight": pixel_weight,
            "source": "html_resource_analysis",
            "severity": "LOW",
        })
        accumulated_score += pixel_weight

    final_score = clamp_score(accumulated_score)
    final_level = determine_risk_level(final_score)

    risk_res = type("obj", (), {"score": final_score, "level": final_level, "signals": signals})()

    # Build human-readable explanations
    total_urls = len(url_results) + len(attachment_url_results) + len(qr_url_results)
    summary_parts = [f"Email contains {total_urls} URLs across body, attachments, and QR codes"]
    if attachments:
        summary_parts.append(f"{len(attachments)} attachment(s)")
    if qr_analysis.get("detected"):
        summary_parts.append(f"{qr_analysis.get('qr_count')} embedded QR code(s)")
    if tracking_analysis.get("detected"):
        summary_parts.append(f"{tracking_analysis.get('tracking_pixels_count')} suspected tracking pixel(s)")

    explanation = {
        "summary": ", ".join(summary_parts),
        "key_reasons": [s.get("reason", "") for s in signals if isinstance(s, dict)],
        "explanations": [s.get("reason", "") for s in signals if isinstance(s, dict)],
    }

    # Canonical Local Threat Intelligence Aggregation across all child indicators
    all_child_evaluations = []
    for u_item in url_results:
        all_child_evaluations.append({
            "indicator": u_item.get("url"),
            "indicator_type": "url",
            "child_artifact": f"body_url:{u_item.get('source', 'body')}",
            "local_ti": u_item.get("local_ti", {}),
        })
    for u_item in attachment_url_results:
        all_child_evaluations.append({
            "indicator": u_item.get("url"),
            "indicator_type": "url",
            "child_artifact": u_item.get("source", "attachment"),
            "local_ti": u_item.get("local_ti", {}),
        })
    for qr_u in qr_url_results:
        all_child_evaluations.append({
            "indicator": qr_u.get("url"),
            "indicator_type": "url",
            "child_artifact": qr_u.get("source", "qr_code"),
            "local_ti": qr_u.get("local_ti", {}),
        })
    for att in attachments:
        att_h = att.get("sha256")
        if att_h:
            h_ti = query_local_threat_intelligence(att_h, "hash")
            all_child_evaluations.append({
                "indicator": att_h,
                "indicator_type": "hash",
                "child_artifact": f"attachment:{att.get('filename')}",
                "local_ti": h_ti,
            })

    aggregated_email_local_ti = aggregate_local_ti_results(all_child_evaluations)

    # Unified list of all discovered URLs for display in the Extracted Email URLs table
    all_unified_urls = list(url_results)
    for att_u in attachment_url_results:
        if not any(x.get("url") == att_u.get("url") for x in all_unified_urls):
            all_unified_urls.append(att_u)
    for qr_u in qr_url_results:
        if not any(x.get("url") == qr_u.get("url") for x in all_unified_urls):
            all_unified_urls.append(qr_u)

    # Machine Learning Assessment for Email (derived from child URLs)
    try:
        from src.features.email_ai_features import extract_email_ai_features
        email_features = extract_email_ai_features(email_data)
    except Exception:
        email_features = {}

    if all_unified_urls:
        valid_ml_candidates = [
            c for c in all_unified_urls
            if isinstance(c.get("ml"), dict) and c["ml"].get("model_available") and c["ml"].get("probability") is not None
        ]
        if valid_ml_candidates:
            best_candidate = max(valid_ml_candidates, key=lambda c: c["ml"]["probability"])
            c_ml = best_candidate["ml"]
            email_ml = {
                "model_available": True,
                "status": "APPLICABLE",
                "model_name": "Random Forest URL Classifier",
                "probability": c_ml.get("probability"),
                "prediction": 1 if c_ml.get("probability", 0) >= 0.5 else 0,
                "evaluated_url": best_candidate.get("url"),
                "features": c_ml.get("features", {}),
                "url_count_evaluated": len(all_unified_urls),
                "note": "ML classification is an independent behavioral/lexical pattern assessment and does not depend on the URL being present in the threat-intelligence database.",
            }
        else:
            first_c = all_unified_urls[0]
            email_ml = {
                "model_available": False,
                "status": "APPLICABLE",
                "model_name": "Random Forest URL Classifier",
                "probability": None,
                "prediction": None,
                "evaluated_url": first_c.get("url"),
                "features": first_c.get("ml", {}).get("features", {}),
                "url_count_evaluated": len(all_unified_urls),
                "note": "Supervised lexical ML model evaluated child URL characteristics.",
            }
    else:
        email_ml = {
            "model_available": False,
            "status": "NOT_APPLICABLE",
            "model_name": "Random Forest URL Classifier",
            "probability": None,
            "prediction": None,
            "features": email_features,
            "note": "ML URL classifier: Not applicable to this artifact type (no URLs present).",
        }

    # VirusTotal policy for email
    if aggregated_email_local_ti.get("found"):
        email_vt = normalize_vt_result({
            "status": "NOT_REQUIRED",
            "message": f"Local threat intelligence match confirmed ({aggregated_email_local_ti.get('source')}); external lookup skipped.",
        }, "")
    else:
        email_vt = normalize_vt_result({
            "status": "NOT_REQUIRED",
            "message": "High evidence sufficiency achieved; external lookup not required.",
        }, "")

    details = {
        "email": email_data,
        "email_headers": headers,
        "email_authentication": auth_results,
        "email_nlp": nlp_results,
        "url_analyses": all_unified_urls,
        "attachments": attachments,
        "attachment_url_analyses": attachment_url_results,
        "qr_analysis": qr_analysis,
        "tracking_analysis": tracking_analysis,
        "sender_domain_intelligence": sender_domain_intel,
        "local_ti": aggregated_email_local_ti,
        "local_threat_intelligence": aggregated_email_local_ti,
        "virustotal": email_vt,
        "ml": email_ml,
    }

    # Build deterministic response
    response = _build_response(
        analysis_id=None,
        artifact_type="email",
        details=details,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )

    response["ml"] = email_ml
    response["local_ti"] = aggregated_email_local_ti
    response["local_threat_intelligence"] = aggregated_email_local_ti
    response["virustotal"] = email_vt

    # Evidence Correlation
    try:
        primary_url_details = url_results[0].get("url_analysis", {}) if url_results else {}
        corr_input = {
            "email_data": email_data,
            "authentication": auth_results,
            "nlp": nlp_results,
            "attachments": attachments,
            "url_details": primary_url_details,
            "qr_analysis": qr_analysis,
        }
        response["evidence_correlation"] = correlate_evidence(corr_input)
    except Exception:
        response["evidence_correlation"] = None

    # Multi-Layer Risk Aggregation
    response["multi_layer_risk"] = aggregate_multi_layer_risk({
        "ml": response.get("ml"),
        "email": email_data,
        "attachment": attachments[0] if attachments else None,
        "qr_analysis": qr_analysis,
        "final_risk": risk_res,
        "correlated_evidence": response.get("evidence_correlation"),
        "explanation": explanation,
    })

    # Evidence Sufficiency
    try:
        from src.analysis.evidence_sufficiency import compute_evidence_sufficiency
        suff = compute_evidence_sufficiency(response)
        suff_dict = {
            "score": suff.score,
            "level": suff.level.value,
            "evidence_classes_present": suff.evidence_classes_present,
            "signals_count": suff.signals_count,
            "has_contradiction": suff.has_contradiction,
            "contradictions": suff.contradictions,
        }
        response["evidence_sufficiency"] = suff_dict
        if "details" in response and isinstance(response["details"], dict):
            response["details"]["evidence_sufficiency"] = suff_dict
    except Exception:
        response["evidence_sufficiency"] = None

    ai_eval = _generate_ai_assessment(response)
    response["ai_analyst"] = ai_eval
    if "details" in response and isinstance(response["details"], dict):
        response["details"]["ai_analyst"] = ai_eval

    return response

# Standardized alias for multi-layer unified email analysis
analyze_email_unified = analyze_email


def analyze_qr(file_path: str, user_id: int) -> Dict[str, Any]:
    from src.features.reputation import normalize_vt_result
    errors = []
    try:
        qr_res = qr_analyzer(file_path)
    except Exception as exc:
        qr_res = {
            "success": False,
            "decode_status": "FAILED",
            "decoded_data": None,
            "decoded_payload": None,
            "payload_type": None,
            "is_url": False,
            "message": str(exc),
        }
        errors.append(str(exc))

    decoded = qr_res.get("decoded_payload") or qr_res.get("decoded_data")
    is_url = qr_res.get("is_url", False)
    payload_type = qr_res.get("payload_type") or ("URL" if is_url else "TEXT")

    if is_url and decoded:
        # Route directly into authoritative central URL pipeline
        url_response = analyze_url(decoded, user_id=user_id)

        # Merge QR metadata
        qr_meta = {
            "artifact_type": "QR",
            "decode_status": "SUCCESS",
            "decoded_payload": decoded,
            "raw_payload": qr_res.get("raw_payload", decoded),
            "payload_type": "URL",
            "is_url": True,
            "downstream_analysis_id": None,
        }

        details = dict(url_response.get("details", {}))
        details["qr"] = qr_meta
        details["url_analysis"] = dict(url_response.get("details", {}))
        details["url"] = decoded
        details["identifier"] = decoded
        details["ml"] = url_response.get("ml")
        details["local_ti"] = url_response.get("local_ti")
        details["virustotal"] = url_response.get("virustotal")

        url_risk = url_response.get("risk", {"score": 0.0, "level": "LOW"})
        risk_score = url_response.get("risk_score", url_risk.get("score", 0.0))
        risk_level = url_response.get("risk_level", url_risk.get("level", "LOW"))

        response = {
            "analysis_id": None,
            "artifact_type": "qr",
            "details": details,
            "risk": url_risk,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": url_response.get("summary", ""),
            "explanation": url_response.get("explanation", {"summary": "Clean QR decoded URL.", "key_reasons": []}),
            "signals": url_response.get("signals", []),
            "errors": errors + url_response.get("errors", []),
            "multi_layer_risk": url_response.get("multi_layer_risk"),
            "evidence_sufficiency": url_response.get("evidence_sufficiency"),
            "ml": url_response.get("ml"),
            "local_ti": url_response.get("local_ti"),
            "virustotal": url_response.get("virustotal"),
            "url": decoded,
            "model_explanation": url_response.get("model_explanation"),
            "evidence_correlation": url_response.get("evidence_correlation"),
        }

        ai_eval = _generate_ai_assessment(response)
        response["ai_analyst"] = ai_eval
        details["ai_analyst"] = ai_eval
        return response

    elif decoded and not is_url:
        # Non-URL QR code payload (e.g. TEXT, EMAIL, PHONE, WIFI, OTHER)
        qr_meta = {
            "artifact_type": "QR",
            "decode_status": "SUCCESS",
            "decoded_payload": decoded,
            "raw_payload": qr_res.get("raw_payload", decoded),
            "payload_type": payload_type,
            "is_url": False,
            "downstream_analysis_id": None,
        }
        ml_not_applicable = {
            "model_available": False,
            "status": "NOT_APPLICABLE",
            "message": "ML URL classifier: Not applicable to this artifact type",
            "probability": None,
            "features": {},
        }
        vt_not_applicable = normalize_vt_result({"status": "NOT_APPLICABLE", "message": "Non-URL QR payload"}, "")
        local_ti_na = {"found": False, "status": "NOT_APPLICABLE"}

        details = {
            "qr": qr_meta,
            "identifier": f"qr:{payload_type.lower()}:{decoded[:40]}",
            "ml": ml_not_applicable,
            "local_ti": local_ti_na,
            "virustotal": vt_not_applicable,
        }
        risk_res = type("obj", (), {"score": 0.0, "level": "LOW", "signals": []})()
        explanation = {
            "summary": f"QR code decoded successfully ({payload_type} payload).",
            "key_reasons": [
                f"Payload Type: {payload_type}",
                f"Decoded Content: {decoded}",
                "Non-URL payloads are evaluated for direct text/data content without web crawlers.",
            ],
        }
        response = _build_response(
            analysis_id=None,
            artifact_type="qr",
            details=details,
            risk_result=risk_res,
            explanation=explanation,
            errors=errors,
        )
        response["ml"] = ml_not_applicable
        response["local_ti"] = local_ti_na
        response["virustotal"] = vt_not_applicable

        suff_dict = {
            "score": 60.0,
            "level": "MEDIUM",
            "evidence_classes": ["qr_payload_decoded"],
            "signals_count": 0,
            "has_contradiction": False,
            "contradictions": [],
        }
        response["evidence_sufficiency"] = suff_dict
        details["evidence_sufficiency"] = suff_dict

        ai_eval = _generate_ai_assessment(response)
        response["ai_analyst"] = ai_eval
        details["ai_analyst"] = ai_eval
        return response

    else:
        # Failed QR extraction
        qr_meta = {
            "artifact_type": "QR",
            "decode_status": "FAILED",
            "decoded_payload": None,
            "raw_payload": None,
            "payload_type": None,
            "is_url": False,
            "message": "No QR code payload extracted.",
        }
        ml_not_applicable = {
            "model_available": False,
            "status": "NOT_APPLICABLE",
            "message": "ML URL classifier: Not applicable to this artifact type",
            "probability": None,
            "features": {},
        }
        vt_not_applicable = normalize_vt_result({"status": "NOT_APPLICABLE", "message": "Unextracted QR payload"}, "")
        local_ti_na = {"found": False, "status": "NOT_EVALUATED"}

        details = {
            "qr": qr_meta,
            "identifier": "qr:unextracted",
            "ml": ml_not_applicable,
            "local_ti": local_ti_na,
            "virustotal": vt_not_applicable,
        }
        risk_res = type("obj", (), {"score": 0.0, "level": "UNKNOWN", "signals": []})()
        explanation = {
            "summary": "No QR code payload extracted.",
            "key_reasons": ["The uploaded image could not be decoded as a valid QR code."],
        }
        response = _build_response(
            analysis_id=None,
            artifact_type="qr",
            details=details,
            risk_result=risk_res,
            explanation=explanation,
            errors=errors,
        )
        response["ml"] = ml_not_applicable
        response["local_ti"] = local_ti_na
        response["virustotal"] = vt_not_applicable

        suff_dict = {
            "score": 0.0,
            "level": "INSUFFICIENT",
            "evidence_classes": [],
            "signals_count": 0,
            "has_contradiction": False,
            "contradictions": [],
        }
        response["evidence_sufficiency"] = suff_dict
        details["evidence_sufficiency"] = suff_dict

        ai_eval = _generate_ai_assessment(response)
        response["ai_analyst"] = ai_eval
        details["ai_analyst"] = ai_eval
        return response

def analyze_file(file_path: str, user_id: int) -> Dict[str, Any]:
    """Analyze an uploaded file artifact using cryptographic hash reputation,
    Local Threat Intelligence, passive attachment structure inspection,
    and embedded URL extraction.
    """
    from src.features.reputation import normalize_vt_result
    errors = []
    
    # 1. Compute SHA-256 strictly from uploaded file bytes
    try:
        file_hash = _sha256_file(file_path).lower().strip()
    except Exception as exc:
        file_hash = ""
        errors.append(f"Hashing error: {exc}")

    # 2. Check Local Threat Intelligence FIRST
    local_ti = query_local_threat_intelligence(file_hash, "hash") if file_hash else {"found": False}

    # 3. Check VirusTotal hash reputation according to policy
    has_vt_key = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
    if local_ti.get("found"):
        # Policy: If local threat intelligence has a confirmed match, skip external VT lookup
        vt_rep = normalize_vt_result({
            "status": "NOT_QUERIED",
            "source": "virustotal",
            "provider": "VirusTotal",
            "malicious": 0,
            "total": 0,
            "message": f"NOT_QUERIED — skipped by policy (confirmed match in local {local_ti.get('source')} threat intelligence).",
            "policy_reason": "SKIPPED_BY_POLICY_LOCAL_MATCH",
        }, file_hash)
    elif file_hash and has_vt_key:
        try:
            vt_rep_raw = get_hash_reputation(file_hash)
            vt_rep = normalize_vt_result(vt_rep_raw, file_hash)
        except Exception as exc:
            errors.append(f"VirusTotal error: {exc}")
            vt_rep = normalize_vt_result({
                "status": "ERROR",
                "error": str(exc),
                "message": f"VirusTotal lookup failed: {exc}",
            }, file_hash)
    elif not has_vt_key:
        vt_rep = normalize_vt_result({
            "status": "UNAVAILABLE",
            "message": "VirusTotal API key not configured.",
        }, file_hash)
    else:
        vt_rep = normalize_vt_result({"status": "ERROR", "error": "Missing file hash"}, "")

    # 4. Static attachment inspection (macro status, OLE/OpenXML structures)
    try:
        attachment_info = attachment_analyzer(file_path)
    except Exception as exc:
        attachment_info = {}
        errors.append(f"Attachment analysis error: {exc}")

    # 5. Embedded URL extraction & inspection
    url_results = []
    try:
        embedded_urls = extract_embedded_urls(file_path)
        for u in embedded_urls:
            try:
                res = url_analyzer(u, check_vt=False)
                risk = analyze_url_risk(res)
                url_results.append({
                    "url": u,
                    "analysis": res,
                    "risk": {
                        "score": getattr(risk, "score", 0),
                        "level": getattr(risk, "level", "UNKNOWN"),
                    }
                })
            except Exception as exc:
                url_results.append({"url": u, "error": str(exc)})
                errors.append(str(exc))
    except Exception as exc:
        errors.append(f"Embedded URL extraction error: {exc}")

    vt_mal = vt_rep.get("malicious", 0) > 0 or vt_rep.get("suspicious", 0) > 0
    max_url_score = max((r["risk"]["score"] for r in url_results if "risk" in r), default=0)

    signals = []
    score = 0.0

    if local_ti.get("found"):
        score = 85.0
        signals.append({
            "name": "Local Threat Intelligence Match",
            "weight": 85.0,
            "reason": f"File hash matched known malware in {local_ti.get('source')}.",
            "source": "local_threat_intelligence",
        })
    elif vt_mal:
        score = 80.0
        signals.append({
            "name": "VirusTotal Detection",
            "weight": 80.0,
            "reason": f"VirusTotal engines reported malicious detections ({vt_rep.get('malicious', 0)} engines).",
            "source": "virustotal",
        })

    # Check for macro detection in attachment
    if attachment_info.get("has_vba_macros") or attachment_info.get("macro_enabled") or attachment_info.get("macro_status") == "MACROS_DETECTED":
        signals.append({
            "name": "VBA Macros Detected",
            "weight": 35.0,
            "reason": f"File contains executable VBA macro code ({attachment_info.get('macro_details', 'Macros present')}).",
            "source": "attachment_analyzer",
        })
        score = max(score, 45.0)

    if max_url_score > 0:
        score = max(score, max_url_score)

    score = clamp_score(score)
    level = determine_risk_level(score)

    risk_res = type("obj", (), {"score": score, "level": level, "signals": signals})()
    ml_not_applicable = {
        "model_available": False,
        "status": "NOT_APPLICABLE",
        "message": "ML URL classifier: Not applicable to this artifact type",
        "probability": None,
        "features": {},
    }

    if score >= 70:
        summary_text = "File flagged as malicious based on threat intelligence or active payload indicators."
    elif score >= 25:
        summary_text = "File exhibits suspicious characteristics requiring further scrutiny."
    elif len(signals) > 0:
        summary_text = "File scanned. Minor informational signals observed."
    else:
        summary_text = "File analysis completed. No malicious indicators or executable macros detected."

    explanation = {
        "summary": summary_text,
        "key_reasons": [s["reason"] for s in signals],
    }
    details = {
        "file_hash": file_hash,
        "hash": file_hash,
        "sha256": file_hash,
        "virustotal": vt_rep,
        "vt_reputation": vt_rep,
        "threat_label": vt_rep.get("threat_label", "Unknown / not provided"),
        "threat_category": vt_rep.get("threat_category", "Unknown"),
        "threat_family": vt_rep.get("threat_family", "Unknown"),
        "local_ti": local_ti,
        "attachment_info": attachment_info,
        "attachments": [attachment_info] if attachment_info else [],
        "embedded_url_analyses": url_results,
        "ml": ml_not_applicable,
    }
    response = _build_response(
        analysis_id=None,
        artifact_type="file",
        details=details,
        risk_result=risk_res,
        explanation=explanation,
        errors=errors,
    )
    response["ml"] = ml_not_applicable
    response["local_ti"] = local_ti
    response["virustotal"] = vt_rep

    try:
        corr_input = {
            "url_details": {"virustotal": vt_rep},
            "attachment": attachment_info,
            "embedded_url_analyses": url_results,
        }
        response["evidence_correlation"] = correlate_evidence(corr_input)
    except Exception:
        response["evidence_correlation"] = None

    response["multi_layer_risk"] = aggregate_multi_layer_risk({
        "attachment": attachment_info,
        "virustotal": vt_rep,
        "final_risk": risk_res,
        "correlated_evidence": response.get("evidence_correlation"),
        "explanation": explanation,
    })

    try:
        from src.analysis.evidence_sufficiency import compute_evidence_sufficiency
        suff = compute_evidence_sufficiency(response)
        suff_dict = {
            "score": suff.score,
            "level": suff.level.value,
            "evidence_classes": suff.evidence_classes_present,
            "signals_count": suff.signals_count,
            "has_contradiction": suff.has_contradiction,
            "contradictions": suff.contradictions,
        }
        response["evidence_sufficiency"] = suff_dict
        details["evidence_sufficiency"] = suff_dict
    except Exception:
        response["evidence_sufficiency"] = None

    ai_eval = _generate_ai_assessment(response)
    response["ai_analyst"] = ai_eval
    details["ai_analyst"] = ai_eval

    return response
