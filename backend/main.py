import uuid
import email
import email.policy
import traceback
import logging
from datetime import datetime, timezone
from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
import os

from backend.config import settings
from backend.database import init_db, save_analysis, get_analysis_by_id, get_recent_analyses
from backend.parser.email_parser import parse_eml
from backend.authentication.spf import evaluate_spf
from backend.authentication.dkim import evaluate_dkim
from backend.authentication.dmarc import evaluate_dmarc
from backend.intelligence.ip_intelligence import analyze_ips
from backend.intelligence.domain_intelligence import analyze_domain
from backend.intelligence.url_intelligence import analyze_urls
from backend.detection.content_analysis import analyze_content
from backend.detection.attachment_analysis import analyze_attachments
from backend.detection.feature_engine import build_feature_vector
from backend.risk.scoring import calculate_risk_score
from backend.risk.ml_model import ml_model_instance
from backend.reports.report_generator import generate_soc_report

# Modular Forensic Services
from backend.services.evidence_service import preserve_evidence
from backend.services.header_forensics import analyze_header_forensics
from backend.services.origin_reconstruction import reconstruct_origin
from backend.services.infrastructure_intelligence import enrich_infrastructure_intelligence
from backend.services.campaign_correlator import build_campaign_graph
from backend.services.confidence_engine import evaluate_investigation_confidence
from backend.services.forensic_report import compile_forensic_findings

# Configure Server Logger
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("analysis")

app = FastAPI(
    title="Email Threat Detection & Forensic Investigation Platform",
    version=settings.VERSION,
    description="Forensic investigation platform analyzing .eml email evidence"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()
    logger.info("[ANALYSIS] Backend initialized and SQLite database ready.")

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"[ANALYSIS] HTTPException: status={exc.status_code}, detail={exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "stage": "API_VALIDATION",
            "error": exc.detail if isinstance(exc.detail, str) else "Request error",
            "details": str(exc.detail)
        }
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error(f"[ANALYSIS] Unhandled Exception: {str(exc)}\n{tb}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "stage": "SERVER_PROCESSING",
            "error": "Forensic analysis failed",
            "details": str(exc)
        }
    )

@app.get("/api/health")
def health_check():
    return {
        "success": True,
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.VERSION,
        "mock_mode": settings.USE_MOCK_INTELLIGENCE
    }

@app.post("/api/analyze")
async def analyze_email(file: UploadFile = File(...)):
    filename = file.filename or "uploaded_email.eml"
    logger.info(f"[1] ANALYSIS REQUEST RECEIVED")
    logger.info(f"[2] FILE RECEIVED: {filename}")

    ext = os.path.splitext(filename)[1].lower()
    valid_exts = {".eml", ".msg", ".txt", ""}
    valid_mimes = {"message/rfc822", "application/octet-stream", "text/plain", "application/x-mime", "text/x-mail", ""}

    # Flexibly validate EML file type
    if ext not in valid_exts and (file.content_type and file.content_type not in valid_mimes):
        logger.warning(f"[ANALYSIS] Rejected file {filename}: ext='{ext}', content_type='{file.content_type}'")
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please select an .EML email file."
        )

    try:
        contents = await file.read()
    except Exception as e:
        logger.error(f"[ANALYSIS] Failed to read file bytes: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Failed to read uploaded file: {str(e)}")

    logger.info(f"[3] FILE READ ({len(contents)} bytes)")

    if not contents or len(contents) == 0:
        logger.warning(f"[ANALYSIS] Empty file uploaded.")
        raise HTTPException(status_code=400, detail="Uploaded EML file is empty.")

    if len(contents) > settings.MAX_FILE_SIZE_BYTES:
        logger.warning(f"[ANALYSIS] File size exceeds limit.")
        raise HTTPException(status_code=400, detail="File size exceeds maximum allowed limit (10MB).")

    try:
        res = run_pipeline(contents, filename)
        logger.info(f"[16] JSON RESPONSE GENERATED")
        return res
    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"[ANALYSIS] Pipeline Exception: {str(e)}\n{tb}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "stage": "FORENSIC_PIPELINE",
                "error": "Forensic analysis failed",
                "details": str(e)
            }
        )

@app.get("/api/samples/{sample_name}")
def analyze_sample_email(sample_name: str):
    logger.info(f"[1] ANALYSIS REQUEST RECEIVED (SAMPLE): {sample_name}")
    sample_path = os.path.join("samples", f"{sample_name}.eml")
    if not os.path.exists(sample_path):
        sample_path = os.path.join("samples", sample_name)
        if not os.path.exists(sample_path):
            raise HTTPException(status_code=404, detail=f"Sample email '{sample_name}' not found.")

    with open(sample_path, "rb") as f:
        contents = f.read()

    return run_pipeline(contents, os.path.basename(sample_path))

def run_pipeline(eml_bytes: bytes, filename: str) -> dict:
    analysis_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now(timezone.utc).isoformat()
    timeline = []

    def log_step(step_name: str, desc: str):
        timeline.append({
            "step": step_name,
            "description": desc,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    # STAGE 1 & 2: RAW EML & EVIDENCE PRESERVATION
    log_step("1. RAW .EML Ingestion", f"Received raw email file '{filename}' for forensic analysis.")
    evidence_meta = preserve_evidence(eml_bytes, filename)
    logger.info(f"[4] SHA256 GENERATED: {evidence_meta['sha256']}")
    log_step("2. EVIDENCE PRESERVATION", f"Preserved evidence {evidence_meta['evidence_id']} (SHA-256: {evidence_meta['sha256'][:16]}...). Integrity VERIFIED.")

    # STAGE 3: THREAT + HEADER FORENSICS
    logger.info(f"[5] EML PARSING STARTED")
    parsed_evidence = parse_eml(eml_bytes)
    logger.info(f"[6] EML PARSING COMPLETED")

    logger.info(f"[7] HEADER FORENSICS STARTED")
    try:
        eml_msg = email.message_from_bytes(eml_bytes, policy=email.policy.default)
    except Exception:
        eml_msg = None

    header_forensics_res = analyze_header_forensics(parsed_evidence, eml_msg)
    
    spf_res = evaluate_spf(parsed_evidence["sender_domain"], parsed_evidence["received_ips"], parsed_evidence["authentication_results"])
    dkim_res = evaluate_dkim(parsed_evidence["headers"]["dkim_signature"], eml_bytes, parsed_evidence["authentication_results"])
    dmarc_res = evaluate_dmarc(parsed_evidence["sender_domain"], spf_res, dkim_res, parsed_evidence["authentication_results"])
    
    authentication_res = {
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res
    }
    logger.info(f"[8] HEADER FORENSICS COMPLETED")

    urls_analyzed = analyze_urls(parsed_evidence["urls"])
    logger.info(f"[9] URL EXTRACTION COMPLETED")

    attachments_analyzed = analyze_attachments(parsed_evidence["attachments"])
    logger.info(f"[10] ATTACHMENT EXTRACTION COMPLETED")

    content_analyzed = analyze_content(parsed_evidence["subject"], parsed_evidence["body_text"], parsed_evidence["body_html"])

    # STAGE 4: TRUST-AWARE ORIGIN RECONSTRUCTION
    ip_intel_raw = analyze_ips(parsed_evidence["received_ips"])
    origin_res = reconstruct_origin(parsed_evidence["received_hops"], ip_intel_raw)
    logger.info(f"[11] ORIGIN RECONSTRUCTION COMPLETED")

    # STAGE 5: INFRASTRUCTURE INTELLIGENCE
    infra_res = enrich_infrastructure_intelligence(
        parsed_evidence["received_ips"],
        parsed_evidence["sender_domain"],
        parsed_evidence["urls"],
        is_mock=settings.USE_MOCK_INTELLIGENCE
    )
    logger.info(f"[12] INFRASTRUCTURE INTELLIGENCE COMPLETED")

    # STAGE 6: CAMPAIGN GRAPH CORRELATION
    campaign_res = build_campaign_graph(
        evidence_meta["evidence_id"],
        parsed_evidence["sender"],
        parsed_evidence["sender_domain"],
        parsed_evidence["headers"]["message_id"],
        urls_analyzed,
        parsed_evidence["attachments"],
        ip_intel_raw
    )
    logger.info(f"[13] CAMPAIGN CORRELATION COMPLETED")

    # STAGE 7: CONFIDENCE-BASED INVESTIGATION
    features = build_feature_vector(
        parsed_evidence, spf_res, dkim_res, dmarc_res,
        ip_intel_raw, infra_res["domain"], header_forensics_res["identity_anomalies"]["lookalike"],
        urls_analyzed, content_analyzed, attachments_analyzed
    )

    details_for_reasons = {
        "lookalike": header_forensics_res["identity_anomalies"]["lookalike"] if header_forensics_res["identity_anomalies"]["lookalike"]["lookalike"] else None,
        "sender": parsed_evidence["sender"],
        "sender_domain": parsed_evidence["sender_domain"],
        "reply_to": parsed_evidence["reply_to"],
        "reply_to_domain": parsed_evidence["reply_to_domain"],
        "dmarc": dmarc_res,
        "urls": urls_analyzed
    }

    risk_assessment = calculate_risk_score(features, details_for_reasons)
    ml_res = ml_model_instance.predict(features)

    confidence_res = evaluate_investigation_confidence(
        risk_assessment["risk_score"],
        features,
        origin_res,
        infra_res,
        campaign_res
    )
    logger.info(f"[14] CONFIDENCE ANALYSIS COMPLETED")

    # STAGE 8: FORENSIC FINDINGS
    report_findings = compile_forensic_findings(
        evidence_meta,
        header_forensics_res,
        authentication_res,
        origin_res,
        infra_res,
        header_forensics_res["identity_anomalies"]["lookalike"],
        urls_analyzed,
        parsed_evidence["attachments"],
        confidence_res,
        risk_assessment["risk_score"],
        risk_assessment["classification"]
    )
    logger.info(f"[15] FORENSIC FINDINGS GENERATED")

    result = {
        "success": True,
        "analysis_id": analysis_id,
        "timestamp": timestamp,
        "filename": filename,
        "risk_score": risk_assessment["risk_score"],
        "risk_level": risk_assessment["classification"],
        "classification": risk_assessment["classification"],
        "verdict": report_findings["overall_verdict"],
        "reasons": risk_assessment["reasons"],
        "is_mock": settings.USE_MOCK_INTELLIGENCE,

        # 8 FORENSIC WORKFLOW STAGES DATA
        "evidence": evidence_meta,
        "header_forensics": header_forensics_res,
        "authentication": authentication_res,
        "origin_reconstruction": origin_res,
        "infrastructure": infra_res,
        "campaign": campaign_res,
        "confidence": confidence_res,
        "findings": report_findings,

        # DASHBOARD CONTRACTS
        "email": {
            "from": parsed_evidence["sender"],
            "to": parsed_evidence["headers"]["to"],
            "reply_to": parsed_evidence["reply_to"],
            "subject": parsed_evidence["subject"],
            "date": parsed_evidence["headers"]["date"],
            "message_id": parsed_evidence["headers"]["message_id"],
            "return_path": parsed_evidence["headers"]["return_path"],
            "sender_domain": parsed_evidence["sender_domain"],
            "reply_to_domain": parsed_evidence["reply_to_domain"],
            "reply_to_mismatch": features["reply_to_mismatch"]
        },
        "lookalike_analysis": header_forensics_res["identity_anomalies"]["lookalike"],
        "domain_intelligence": infra_res["domain"],
        "domains": parsed_evidence["domains"],
        "urls": urls_analyzed,
        "attachments": parsed_evidence["attachments"],
        "content_analysis": content_analyzed,
        "attachment_analysis": attachments_analyzed,
        "features": features,
        "ml_threat_analysis": ml_res,
        "investigation_timeline": timeline
    }

    # Persist in SQLite
    save_analysis(result)

    return result

@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    res = get_analysis_by_id(analysis_id)
    if not res:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return {"success": True, "analysis": res}

@app.get("/api/analysis/{analysis_id}/report", response_class=PlainTextResponse)
def get_analysis_report(analysis_id: str):
    res = get_analysis_by_id(analysis_id)
    if not res:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return generate_soc_report(res)

@app.get("/api/history")
def get_history(limit: int = Query(default=10, le=50)):
    return {"success": True, "history": get_recent_analyses(limit)}
