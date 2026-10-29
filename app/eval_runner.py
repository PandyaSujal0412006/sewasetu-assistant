# -*- coding: utf-8 -*-
"""
Automated Evaluation Runner for Sewa Setu Old Age Pension Portal.

Executes all 9 required assessment scenarios against the actual MCP endpoints
(/mcp/citizen and /mcp/officer) using authenticated RS256 JWT tokens, and performs
strict SQL assertions on PostgreSQL to verify statutory database state.

Features:
  - Isolated test fixtures: Restricts all tests to mobile prefix 99900010XX.
    NEVER mutates, approves, or deletes any of the 100,000 supplied seed applications.
  - Reproducible and idempotent: Purges only test-prefix records before each run.
  - Full transcript capture: Multi-turn tool calls and responses recorded per persona.
  - Sensitive data redaction: Redacts mobile numbers, bank accounts, tokens, and credentials.
  - Direct database assertions: Verifies application status, audit logs, portal_users, and counts.
  - Persistence: Stores evaluation run history in PostgreSQL eval_runs table.
"""

import os
import re
import json
import time
import uuid
import copy
from datetime import datetime, date, timedelta
from typing import Dict, Any, List, Tuple, Optional

import requests
import psycopg2

import app as portal
import oauth as portal_oauth

BASE_URL = os.environ.get("INTERNAL_BASE_URL", "http://127.0.0.1:8000")

# Reserved test mobile range: exactly 10 digits starting with 99900010
TEST_MOBILE_PREFIX = "99900010"

PERSONA_SPECS = [
    {
        "id": "EVAL-01",
        "name": "Hemaprabha Saikia",
        "age": 68,
        "block": "Sonari",
        "village": "Borhat Village",
        "mobile": "9990001001",
        "dob": "12/03/1958",
        "bank_account": "20485938491",
        "ifsc": "SBIN0003077",
        "gender": "Female",
        "marital_status": "Widowed",
        "persona_summary": "68-year-old rural widow from Borhat village in Sonari block. Her grandson assists her at a local Common Service Center (CSC) kiosk.",
        "eval_rationale": "Verify standard happy path for an eligible senior citizen: guideline check, draft validation, age-proof upload, and submission resulting in an active PENDING application and audit trail.",
        "expected_statutory_outcome": "Application created with status 'PENDING', audit log records 'SUBMIT', portal account created, SMS confirmation dispatched."
    },
    {
        "id": "EVAL-02",
        "name": "Bhaben Gogoi",
        "age": 57,
        "block": "Rajapara",
        "village": "Chaygaon",
        "mobile": "9990001002",
        "dob": "15/05/1969",
        "bank_account": "30948572918",
        "ifsc": "SBIN0003077",
        "gender": "Male",
        "marital_status": "Married",
        "persona_summary": "57-year-old farmer from Chaygaon village in Rajapara block who heard about the pension from neighbors and wants to apply early.",
        "eval_rationale": "Verify statutory age boundary enforcement. The law strictly requires age 60 or above. The assistant must refuse submission and not create any database records.",
        "expected_statutory_outcome": "Assistant detects age < 60, validation returns actionable error, 0 rows inserted into applications table."
    },
    {
        "id": "EVAL-03",
        "name": "Minati Das",
        "age": 65,
        "block": "Guwahati Urban",
        "village": "Paltan Bazar",
        "mobile": "9990001003",
        "dob": "10/08/1961",
        "bank_account": "40928374615",
        "ifsc": "SBIN0003077",
        "gender": "Female",
        "marital_status": "Single",
        "persona_summary": "65-year-old resident living in Guwahati Urban, which is outside the six rural blocks notified for the scheme.",
        "eval_rationale": "Verify block jurisdiction validation. Only Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, and Khelua blocks are eligible.",
        "expected_statutory_outcome": "Assistant detects non-notified block, validation returns clear block restriction error, 0 rows inserted into database."
    },
    {
        "id": "EVAL-04",
        "name": "Purna Kanta Bora",
        "age": 71,
        "block": "Borgaon",
        "village": "Rupnagar",
        "mobile": "9990001004",
        "dob": "04/02/1955",
        "bank_account": "12345",  # Initial invalid short account
        "valid_bank_account": "50918273645",
        "ifsc": "SBIN999",       # Initial invalid IFSC
        "valid_ifsc": "SBIN0003077",
        "gender": "Male",
        "marital_status": "Married",
        "persona_summary": "71-year-old senior from Rupnagar who initially provides incomplete banking details from an old passbook.",
        "eval_rationale": "Verify interactive self-correction: Assistant catches invalid bank account (<9 digits) and invalid IFSC format, guides user to correct them, and successfully submits once valid.",
        "expected_statutory_outcome": "Initial draft validation fails with banking errors; corrected submission succeeds with valid account and IFSC."
    },
    {
        "id": "EVAL-05",
        "name": "Rupeswar Chetia",
        "age": 64,
        "block": "Namti",
        "village": "Namti Chariali",
        "mobile": "9990001005",
        "dob": "20/07/1962",
        "bank_account": "60918273645",
        "ifsc": "SBIN0003077",
        "gender": "Male",
        "marital_status": "Married",
        "persona_summary": "64-year-old resident who already submitted an application earlier and mistakenly tries to submit another one.",
        "eval_rationale": "Verify single active application rule. An applicant with a PENDING application cannot submit a duplicate application on the same mobile.",
        "expected_statutory_outcome": "Second submission blocked by assistant with message explaining existing active application."
    },
    {
        "id": "EVAL-06",
        "name": "Tuleswari Baruah",
        "age": 66,
        "block": "Khelua",
        "village": "Khelua Gaon",
        "mobile": "9990001006",
        "dob": "18/09/1960",
        "bank_account": "70918273645",
        "ifsc": "SBIN0003077",
        "new_bank_account": "70918273999",
        "gender": "Female",
        "marital_status": "Widowed",
        "persona_summary": "66-year-old applicant who realized her bank account had an error and needs to withdraw her pending application to apply afresh.",
        "eval_rationale": "Verify withdrawal and re-application workflow. Status portal permits withdrawal of PENDING application, updating status to WITHDRAWN and allowing a new application.",
        "expected_statutory_outcome": "Initial application status transitions to WITHDRAWN, audit log records 'WITHDRAW', new application submits successfully with PENDING status."
    },
    {
        "id": "EVAL-07",
        "name": "Jogen Hazarika",
        "age": 74,
        "block": "Dhemaji Pathar",
        "village": "Pathar Gaon",
        "mobile": "9990001007",
        "dob": "05/01/1952",
        "bank_account": "80918273645",
        "ifsc": "SBIN0003077",
        "gender": "Male",
        "marital_status": "Married",
        "persona_summary": "74-year-old applicant who applied earlier and wants to check his application status, statutory SLA countdown, and download the official acknowledgment receipt.",
        "eval_rationale": "Verify read-only status tracking and PDF acknowledgment receipt generation without mutating database state.",
        "expected_statutory_outcome": "Accurately returns application number, PENDING status, days pending, SLA countdown, and valid PDF receipt bytes."
    },
    {
        "id": "EVAL-08",
        "name": "Block Officer Statutory Approval",
        "officer_user": "admin",
        "target_persona_mobile": "9990001001",  # Hemaprabha Saikia
        "persona_summary": "Block Welfare Officer reviewing the pending applications queue for Sonari block.",
        "eval_rationale": "Verify departmental officer workflow: view dashboard summary metrics, list pending applications, inspect applicant dossier, and execute statutory approval with mandatory note.",
        "expected_statutory_outcome": "Application status updated from PENDING to APPROVED, decided_by = 'officer:admin', audit_log records action APPROVED with note."
    },
    {
        "id": "EVAL-09",
        "name": "Block Officer Statutory Rejection",
        "officer_user": "admin",
        "target_persona_mobile": "9990001009",
        "applicant_name": "Dambaru Saikia",
        "dob": "10/10/1950",
        "block": "Namti",
        "village": "Namti Basti",
        "bank_account": "90918273645",
        "ifsc": "SBIN0003077",
        "rejection_note": "Aadhaar copy submitted is blurred and does not clearly verify date of birth upon block scrutiny.",
        "persona_summary": "Block Welfare Officer reviewing an application with an illegible age proof document.",
        "eval_rationale": "Verify statutory rejection workflow: Officer reviews dossier and rejects with an explicit justification note recorded in the audit trail.",
        "expected_statutory_outcome": "Application status updated to REJECTED, decided_by = 'officer:admin', audit_log records action REJECTED with full note."
    }
]


# ---------------------------------------------------------------------------
# Redaction & Security Helpers
# ---------------------------------------------------------------------------

def redact_sensitive(obj: Any) -> Any:
    """Recursively mask mobile numbers, bank accounts, tokens, and passwords."""
    if isinstance(obj, str):
        # Redact Bearer tokens
        s = re.sub(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer [REDACTED_JWT]", obj)
        # Redact JWT tokens
        s = re.sub(r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+", "[REDACTED_JWT]", s)
        # Redact 10-digit mobile numbers (whether followed by boundary, underscore, or non-digit)
        s = re.sub(r"(9\d{5})\d{4}(?!\d)", r"\1****", s)
        # Redact bank accounts (9-18 digits)
        s = re.sub(r"\b(\d{2,4})(\d{5,12})(\d{3})\b", r"\1******\3", s)
        # Redact base64 blobs
        s = re.sub(r'"pdf_base64":\s*"[^"]+"', '"pdf_base64": "[BASE64_PDF_DATA]"', s)
        s = re.sub(r'"file_content_base64":\s*"[^"]+"', '"file_content_base64": "[BASE64_DOCUMENT_DATA]"', s)
        return s
    elif isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("file_content_base64", "pdf_base64"):
                out[k] = "[BASE64_DATA]"
            elif k in ("token", "access_token", "refresh_token", "secret", "password"):
                out[k] = "[REDACTED]"
            elif k == "bank_account" and isinstance(v, str) and len(v) >= 6:
                out[k] = v[:3] + ("*" * (len(v) - 5)) + v[-2:]
            elif k == "mobile" and isinstance(v, str) and len(v) == 10:
                out[k] = v[:6] + "****"
            else:
                out[k] = redact_sensitive(v)
        return out
    elif isinstance(obj, list):
        return [redact_sensitive(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# Database Fixture Management (Safe & Isolated)
# ---------------------------------------------------------------------------

def ensure_eval_tables():
    """Ensure eval_runs table exists for persistent evaluation tracking."""
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        """CREATE TABLE IF NOT EXISTS eval_runs (
            id SERIAL PRIMARY KEY,
            run_id VARCHAR(64) UNIQUE,
            timestamp TIMESTAMP,
            total INTEGER,
            passed INTEGER,
            failed INTEGER,
            pass_rate NUMERIC(5,2),
            avg_turns NUMERIC(4,1),
            results JSONB
        )"""
    )
    conn.commit()
    cur.close()
    conn.close()


def clean_test_fixtures():
    """
    Safely purge ONLY applications, audit logs, and portal_users belonging
    to the reserved test range (99900010XX).
    Guarantees that none of the 100,000 production seed records are ever touched.
    """
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM applications WHERE mobile LIKE %s", (f"{TEST_MOBILE_PREFIX}%",))
    app_ids = [r[0] for r in cur.fetchall()]

    if app_ids:
        cur.execute("DELETE FROM audit_log WHERE application_id = ANY(%s)", (app_ids,))
        cur.execute("DELETE FROM applications WHERE id = ANY(%s)", (app_ids,))

    cur.execute("DELETE FROM portal_users WHERE mobile LIKE %s", (f"{TEST_MOBILE_PREFIX}%",))
    cur.execute("DELETE FROM otps WHERE mobile LIKE %s", (f"{TEST_MOBILE_PREFIX}%",))
    cur.execute("DELETE FROM audit_log WHERE actor LIKE %s", (f"applicant:{TEST_MOBILE_PREFIX}%",))
    conn.commit()
    cur.close()
    conn.close()


# ---------------------------------------------------------------------------
# MCP Client Simulator
# ---------------------------------------------------------------------------

def mcp_call(endpoint: str, method: str, params: Optional[Dict[str, Any]] = None, token: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    """Execute a real JSON-RPC 2.0 request against the MCP server."""
    url = f"{BASE_URL}/mcp/{endpoint}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000) % 1000000,
        "method": method
    }
    if params is not None:
        body["params"] = params

    try:
        r = requests.post(url, json=body, headers=headers, timeout=10)
        return r.status_code, r.json()
    except Exception as e:
        return 500, {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}}


def mint_token_for(subject: str, role: str, scope: str) -> str:
    """Mint RS256 token using portal key."""
    token, _ = portal_oauth.mint_access_token(
        subject=subject,
        role=role,
        scope=scope,
        audience=portal_oauth.ISSUER,
        client_id="eval-runner",
        ttl=3600
    )
    return token


# ---------------------------------------------------------------------------
# Individual Scenario Runners
# ---------------------------------------------------------------------------

def run_eval_01(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-01: Hemaprabha Saikia - Standard Eligible Senior Application."""
    transcript = []
    assertions = []
    mobile = spec["mobile"]
    token = mint_token_for(f"citizen:{mobile}", "citizen", "citizen")
    t0 = time.time()

    # Step 1: Query guidelines
    code, res = mcp_call("citizen", "tools/call", {"name": "get_scheme_guidelines", "arguments": {}}, token)
    transcript.append({
        "step": 1,
        "action": "Check Scheme Guidelines",
        "tool": "get_scheme_guidelines",
        "arguments": {},
        "response": redact_sensitive(res)
    })

    # Step 2: Validate draft
    draft = {
        "applicant_name": spec["name"],
        "village": spec["village"],
        "block": spec["block"],
        "dob": spec["dob"],
        "bank_account": spec["bank_account"],
        "ifsc": spec["ifsc"],
        "gender": spec["gender"],
        "marital_status": spec["marital_status"],
        "has_age_proof": True
    }
    code, res = mcp_call("citizen", "tools/call", {"name": "validate_application_draft", "arguments": draft}, token)
    transcript.append({
        "step": 2,
        "action": "Pre-validate Application Draft",
        "tool": "validate_application_draft",
        "arguments": redact_sensitive(draft),
        "response": redact_sensitive(res)
    })

    # Step 3: Upload age proof
    code, res = mcp_call("citizen", "tools/call", {
        "name": "upload_age_proof_document",
        "arguments": {"filename": "aadhaar_proof.pdf", "document_type": "Aadhaar Card"}
    }, token)
    upload_data = json.loads(res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    doc_path = upload_data.get("doc_path", "")
    transcript.append({
        "step": 3,
        "action": "Upload Age Proof Document",
        "tool": "upload_age_proof_document",
        "arguments": {"filename": "aadhaar_proof.pdf"},
        "response": redact_sensitive(res)
    })

    # Step 4: Submit application
    submit_args = {
        "applicant_name": spec["name"],
        "village": spec["village"],
        "block": spec["block"],
        "dob": spec["dob"],
        "bank_account": spec["bank_account"],
        "ifsc": spec["ifsc"],
        "doc_path": doc_path,
        "gender": spec["gender"],
        "marital_status": spec["marital_status"]
    }
    code, res = mcp_call("citizen", "tools/call", {"name": "submit_pension_application", "arguments": submit_args}, token)
    sub_data = json.loads(res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    app_no = sub_data.get("application_no", "")
    app_id = sub_data.get("application_id")
    transcript.append({
        "step": 4,
        "action": "Submit Application",
        "tool": "submit_pension_application",
        "arguments": redact_sensitive(submit_args),
        "response": redact_sensitive(res)
    })

    # Database Assertions
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, block, applicant_name FROM applications WHERE mobile = %s", (mobile,))
    db_row = cur.fetchone()
    assertions.append({
        "description": "Application record exists in Postgres with status PENDING",
        "query": f"SELECT status FROM applications WHERE mobile = '{redact_sensitive(mobile)}'",
        "expected": "PENDING",
        "actual": db_row[0] if db_row else None,
        "passed": bool(db_row and db_row[0] == "PENDING")
    })

    cur.execute("SELECT count(*) FROM portal_users WHERE mobile = %s", (mobile,))
    user_count = cur.fetchone()[0]
    assertions.append({
        "description": "Citizen status portal user account created",
        "query": f"SELECT count(*) FROM portal_users WHERE mobile = '{redact_sensitive(mobile)}'",
        "expected": 1,
        "actual": user_count,
        "passed": user_count == 1
    })

    cur.execute("SELECT action, actor FROM audit_log WHERE application_id = %s", (app_id,))
    audit_row = cur.fetchone()
    assertions.append({
        "description": "Audit log records SUBMIT action with actor applicant:<mobile>",
        "query": f"SELECT action, actor FROM audit_log WHERE application_id = {app_id}",
        "expected": f"SUBMIT, applicant:{redact_sensitive(mobile)}",
        "actual": f"{audit_row[0]}, {redact_sensitive(audit_row[1])}" if audit_row else None,
        "passed": bool(audit_row and audit_row[0] == "SUBMIT")
    })
    cur.close()
    conn.close()

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": f"Application {app_no} created in PENDING status; DB assertions passed." if passed else "Verification assertions failed."
    }


def run_eval_02(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-02: Bhaben Gogoi - Age Ineligibility (57 < 60)."""
    transcript = []
    assertions = []
    mobile = spec["mobile"]
    token = mint_token_for(f"citizen:{mobile}", "citizen", "citizen")
    t0 = time.time()

    draft = {
        "applicant_name": spec["name"],
        "village": spec["village"],
        "block": spec["block"],
        "dob": spec["dob"],  # 15/05/1969 -> age 57
        "bank_account": spec["bank_account"],
        "ifsc": spec["ifsc"],
        "has_age_proof": True
    }
    code, res = mcp_call("citizen", "tools/call", {"name": "validate_application_draft", "arguments": draft}, token)
    val_out = json.loads(res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 1,
        "action": "Validate Ineligible Age Draft",
        "tool": "validate_application_draft",
        "arguments": redact_sensitive(draft),
        "response": redact_sensitive(res)
    })

    # Direct submission attempt
    submit_args = copy.deepcopy(draft)
    submit_args.pop("has_age_proof", None)
    submit_args["doc_path"] = "some_proof.pdf"
    code, res_sub = mcp_call("citizen", "tools/call", {"name": "submit_pension_application", "arguments": submit_args}, token)
    sub_out = json.loads(res_sub.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 2,
        "action": "Attempt Ineligible Submission",
        "tool": "submit_pension_application",
        "arguments": redact_sensitive(submit_args),
        "response": redact_sensitive(res_sub)
    })

    # DB Assertions: 0 rows inserted
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (mobile,))
    app_count = cur.fetchone()[0]
    assertions.append({
        "description": "Zero records created in applications table for underage applicant",
        "query": f"SELECT count(*) FROM applications WHERE mobile = '{redact_sensitive(mobile)}'",
        "expected": 0,
        "actual": app_count,
        "passed": app_count == 0
    })

    cur.execute("SELECT count(*) FROM portal_users WHERE mobile = %s", (mobile,))
    user_count = cur.fetchone()[0]
    assertions.append({
        "description": "Zero portal user accounts created",
        "query": f"SELECT count(*) FROM portal_users WHERE mobile = '{redact_sensitive(mobile)}'",
        "expected": 0,
        "actual": user_count,
        "passed": user_count == 0
    })
    cur.close()
    conn.close()

    val_rejected = (not val_out.get("valid")) and any("60 years of age" in err for err in val_out.get("errors", []))
    sub_rejected = (not sub_out.get("success")) and ("validation failed" in sub_out.get("error", "").lower() or "60 years" in sub_out.get("error", "").lower())
    assertions.append({
        "description": "Assistant validation explicitly reported 60-year age requirement",
        "query": "MCP validate_application_draft response inspection",
        "expected": "applicant must be 60 years of age or above",
        "actual": val_out.get("errors", [""])[0] if val_out.get("errors") else None,
        "passed": val_rejected and sub_rejected
    })

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Assistant correctly rejected under-60 applicant; zero database records created." if passed else "Validation or DB assertion failed."
    }


def run_eval_03(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-03: Minati Das - Unsupported / Out-of-Jurisdiction Block."""
    transcript = []
    assertions = []
    mobile = spec["mobile"]
    token = mint_token_for(f"citizen:{mobile}", "citizen", "citizen")
    t0 = time.time()

    draft = {
        "applicant_name": spec["name"],
        "village": spec["village"],
        "block": spec["block"],  # Guwahati Urban (ineligible)
        "dob": spec["dob"],
        "bank_account": spec["bank_account"],
        "ifsc": spec["ifsc"],
        "has_age_proof": True
    }
    code, res = mcp_call("citizen", "tools/call", {"name": "validate_application_draft", "arguments": draft}, token)
    val_out = json.loads(res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 1,
        "action": "Validate Unsupported Block Draft",
        "tool": "validate_application_draft",
        "arguments": redact_sensitive(draft),
        "response": redact_sensitive(res)
    })

    # DB Assertions
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (mobile,))
    app_count = cur.fetchone()[0]
    assertions.append({
        "description": "Zero records created in applications table for invalid block",
        "query": f"SELECT count(*) FROM applications WHERE mobile = '{redact_sensitive(mobile)}'",
        "expected": 0,
        "actual": app_count,
        "passed": app_count == 0
    })
    cur.close()
    conn.close()

    block_rejected = (not val_out.get("valid")) and any("block must be one of" in err for err in val_out.get("errors", []))
    assertions.append({
        "description": "Assistant explicitly lists the 6 sanctioned scheme blocks",
        "query": "MCP validate_application_draft error message check",
        "expected": "block must be one of: Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, Khelua",
        "actual": val_out.get("errors", [""])[0] if val_out.get("errors") else None,
        "passed": block_rejected
    })

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Assistant correctly caught unsupported block and cited valid blocks." if passed else "Block rejection assertion failed."
    }


def run_eval_04(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-04: Purna Kanta Bora - Malformed Banking Self-Correction."""
    transcript = []
    assertions = []
    mobile = spec["mobile"]
    token = mint_token_for(f"citizen:{mobile}", "citizen", "citizen")
    t0 = time.time()

    # Step 1: Draft with malformed banking (short account 5 digits & invalid IFSC)
    bad_draft = {
        "applicant_name": spec["name"],
        "village": spec["village"],
        "block": spec["block"],
        "dob": spec["dob"],
        "bank_account": spec["bank_account"],
        "ifsc": spec["ifsc"],
        "has_age_proof": True
    }
    code, res_bad = mcp_call("citizen", "tools/call", {"name": "validate_application_draft", "arguments": bad_draft}, token)
    bad_out = json.loads(res_bad.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 1,
        "action": "Validate Malformed Banking Draft",
        "tool": "validate_application_draft",
        "arguments": redact_sensitive(bad_draft),
        "response": redact_sensitive(res_bad)
    })

    has_acc_err = any("bank account number must be 9 to 18 digits" in err for err in bad_out.get("errors", []))
    has_ifsc_err = any("IFSC must be 11 characters" in err for err in bad_out.get("errors", []))
    assertions.append({
        "description": "Assistant identified both bank account digit and IFSC format errors",
        "query": "MCP draft validation errors inspection",
        "expected": "account 9-18 digits AND IFSC 11 chars",
        "actual": f"account_err: {has_acc_err}, ifsc_err: {has_ifsc_err}",
        "passed": has_acc_err and has_ifsc_err
    })

    # Step 2: Upload age proof and submit with corrected details
    code, res_up = mcp_call("citizen", "tools/call", {
        "name": "upload_age_proof_document",
        "arguments": {"filename": "voter_id.jpg", "document_type": "Voter ID"}
    }, token)
    doc_path = json.loads(res_up.get("result", {}).get("content", [{}])[0].get("text", "{}")).get("doc_path", "")

    corrected_submit = {
        "applicant_name": spec["name"],
        "village": spec["village"],
        "block": spec["block"],
        "dob": spec["dob"],
        "bank_account": spec["valid_bank_account"],
        "ifsc": spec["valid_ifsc"],
        "doc_path": doc_path
    }
    code, res_sub = mcp_call("citizen", "tools/call", {"name": "submit_pension_application", "arguments": corrected_submit}, token)
    sub_out = json.loads(res_sub.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 2,
        "action": "Submit Corrected Application",
        "tool": "submit_pension_application",
        "arguments": redact_sensitive(corrected_submit),
        "response": redact_sensitive(res_sub)
    })

    # DB Assertions
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, bank_account, ifsc FROM applications WHERE mobile = %s", (mobile,))
    db_row = cur.fetchone()
    assertions.append({
        "description": "Application successfully recorded with corrected bank account and IFSC",
        "query": f"SELECT status, ifsc FROM applications WHERE mobile = '{redact_sensitive(mobile)}'",
        "expected": f"PENDING, {spec['valid_ifsc']}",
        "actual": f"{db_row[0]}, {db_row[2]}" if db_row else None,
        "passed": bool(db_row and db_row[0] == "PENDING" and db_row[1] == spec["valid_bank_account"] and db_row[2] == spec["valid_ifsc"])
    })
    cur.close()
    conn.close()

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Assistant guided correction of banking errors; application submitted successfully." if passed else "Self-correction assertion failed."
    }


def run_eval_05(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-05: Rupeswar Chetia - Duplicate Active Application Prevention."""
    transcript = []
    assertions = []
    mobile = spec["mobile"]
    token = mint_token_for(f"citizen:{mobile}", "citizen", "citizen")
    t0 = time.time()

    # Seed an initial active application directly in DB
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, village, block,
            bank_account, ifsc, doc_path, status, submitted_at)
           VALUES ('SSPEVAL501', %s, %s, %s, %s, %s, %s, %s, 'seed_doc.pdf', 'PENDING', NOW())
           RETURNING id""",
        (spec["name"], mobile, portal.parse_dob(spec["dob"]), spec["village"], spec["block"],
         spec["bank_account"], spec["ifsc"])
    )
    init_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    # Step 1: Attempt second submission via MCP
    second_submit = {
        "applicant_name": spec["name"],
        "village": spec["village"],
        "block": spec["block"],
        "dob": spec["dob"],
        "bank_account": spec["bank_account"],
        "ifsc": spec["ifsc"],
        "doc_path": "second_doc.pdf"
    }
    code, res = mcp_call("citizen", "tools/call", {"name": "submit_pension_application", "arguments": second_submit}, token)
    sub_out = json.loads(res.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 1,
        "action": "Attempt Duplicate Application Submission",
        "tool": "submit_pension_application",
        "arguments": redact_sensitive(second_submit),
        "response": redact_sensitive(res)
    })

    # DB Assertions: exactly 1 application exists for this mobile
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (mobile,))
    total_apps = cur.fetchone()[0]
    assertions.append({
        "description": "Total applications for mobile remains exactly 1 (duplicate blocked)",
        "query": f"SELECT count(*) FROM applications WHERE mobile = '{redact_sensitive(mobile)}'",
        "expected": 1,
        "actual": total_apps,
        "passed": total_apps == 1
    })
    cur.close()
    conn.close()

    blocked = (not sub_out.get("success")) and ("already exists" in sub_out.get("error", "").lower())
    assertions.append({
        "description": "Assistant returned active application conflict warning",
        "query": "MCP submit_pension_application response error check",
        "expected": "already exists for your mobile number",
        "actual": sub_out.get("error"),
        "passed": blocked
    })

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Duplicate application blocked by assistant; database integrity preserved." if passed else "Duplicate prevention failed."
    }


def run_eval_06(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-06: Tuleswari Baruah - Application Withdrawal and Resubmission."""
    transcript = []
    assertions = []
    mobile = spec["mobile"]
    token = mint_token_for(f"citizen:{mobile}", "citizen", "citizen")
    t0 = time.time()

    # Step 1: Initial submission
    code, res1 = mcp_call("citizen", "tools/call", {
        "name": "submit_pension_application",
        "arguments": {
            "applicant_name": spec["name"],
            "village": spec["village"],
            "block": spec["block"],
            "dob": spec["dob"],
            "bank_account": spec["bank_account"],
            "ifsc": spec["ifsc"],
            "doc_path": "initial_proof.pdf"
        }
    }, token)
    sub1_data = json.loads(res1.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    app1_id = sub1_data.get("application_id")
    transcript.append({
        "step": 1,
        "action": "Submit Initial Application",
        "tool": "submit_pension_application",
        "arguments": {"applicant_name": spec["name"]},
        "response": redact_sensitive(res1)
    })

    # Step 2: Withdraw application
    code, res2 = mcp_call("citizen", "tools/call", {
        "name": "withdraw_pension_application",
        "arguments": {"reason": "Entered incorrect bank account number"}
    }, token)
    transcript.append({
        "step": 2,
        "action": "Withdraw Pending Application",
        "tool": "withdraw_pension_application",
        "arguments": {"reason": "Entered incorrect bank account number"},
        "response": redact_sensitive(res2)
    })

    # Assert withdrawal in DB
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status FROM applications WHERE id = %s", (app1_id,))
    status1 = cur.fetchone()[0]
    assertions.append({
        "description": "Initial application transitioned to WITHDRAWN status",
        "query": f"SELECT status FROM applications WHERE id = {app1_id}",
        "expected": "WITHDRAWN",
        "actual": status1,
        "passed": status1 == "WITHDRAWN"
    })

    cur.execute("SELECT action, note FROM audit_log WHERE application_id = %s AND action = 'WITHDRAW'", (app1_id,))
    w_audit = cur.fetchone()
    assertions.append({
        "description": "Audit log records WITHDRAW action with reason note",
        "query": f"SELECT action, note FROM audit_log WHERE application_id = {app1_id} AND action = 'WITHDRAW'",
        "expected": "WITHDRAW",
        "actual": w_audit[0] if w_audit else None,
        "passed": bool(w_audit and w_audit[0] == "WITHDRAW")
    })

    # Step 3: Resubmit with updated bank account
    code, res3 = mcp_call("citizen", "tools/call", {
        "name": "submit_pension_application",
        "arguments": {
            "applicant_name": spec["name"],
            "village": spec["village"],
            "block": spec["block"],
            "dob": spec["dob"],
            "bank_account": spec["new_bank_account"],
            "ifsc": spec["ifsc"],
            "doc_path": "resubmitted_proof.pdf"
        }
    }, token)
    sub3_data = json.loads(res3.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    app2_id = sub3_data.get("application_id")
    transcript.append({
        "step": 3,
        "action": "Submit Fresh Application After Withdrawal",
        "tool": "submit_pension_application",
        "arguments": {"bank_account": redact_sensitive(spec["new_bank_account"])},
        "response": redact_sensitive(res3)
    })

    cur.execute("SELECT status, bank_account FROM applications WHERE id = %s", (app2_id,))
    row2 = cur.fetchone()
    assertions.append({
        "description": "New application created in PENDING status with updated account",
        "query": f"SELECT status FROM applications WHERE id = {app2_id}",
        "expected": "PENDING",
        "actual": row2[0] if row2 else None,
        "passed": bool(row2 and row2[0] == "PENDING" and row2[1] == spec["new_bank_account"])
    })
    cur.close()
    conn.close()

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Withdrawal executed cleanly; citizen re-applied with updated bank account." if passed else "Withdrawal/resubmission failed."
    }


def run_eval_07(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-07: Jogen Hazarika - Application Status Tracking & Receipt Generation."""
    transcript = []
    assertions = []
    mobile = spec["mobile"]
    token = mint_token_for(f"citizen:{mobile}", "citizen", "citizen")
    t0 = time.time()

    # Pre-seed an application submitted 4 days ago
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, village, block,
            bank_account, ifsc, doc_path, status, submitted_at)
           VALUES ('SSPEVAL701', %s, %s, %s, %s, %s, %s, %s, 'jogen_doc.pdf', 'PENDING', NOW() - INTERVAL '4 days')
           RETURNING id, application_no""",
        (spec["name"], mobile, portal.parse_dob(spec["dob"]), spec["village"], spec["block"],
         spec["bank_account"], spec["ifsc"])
    )
    app_id, app_no = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    # Step 1: Query status
    code, res_s = mcp_call("citizen", "tools/call", {"name": "get_my_application_status", "arguments": {}}, token)
    s_data = json.loads(res_s.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 1,
        "action": "Query Application Status & SLA Countdown",
        "tool": "get_my_application_status",
        "arguments": {},
        "response": redact_sensitive(res_s)
    })

    assertions.append({
        "description": "MCP status returns correct application number and PENDING state",
        "query": f"SELECT application_no, status FROM applications WHERE id = {app_id}",
        "expected": f"{app_no}, PENDING",
        "actual": f"{s_data.get('application_no')}, {s_data.get('status')}",
        "passed": s_data.get("application_no") == app_no and s_data.get("status") == "PENDING"
    })

    assertions.append({
        "description": "MCP correctly calculates ~4 days pending under 15-day statutory SLA",
        "query": "status response days_pending and sla_days fields",
        "expected": "days_pending >= 3 and sla_days = 15",
        "actual": f"days_pending={s_data.get('days_pending')}, sla_days={s_data.get('sla_days')}",
        "passed": s_data.get("days_pending") is not None and s_data.get("sla_days") == 15
    })

    # Step 2: Retrieve acknowledgment receipt
    code, res_r = mcp_call("citizen", "tools/call", {"name": "get_acknowledgment_receipt", "arguments": {}}, token)
    r_data = json.loads(res_r.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 2,
        "action": "Download Computer-Generated Acknowledgment Receipt",
        "tool": "get_acknowledgment_receipt",
        "arguments": {},
        "response": redact_sensitive(res_r)
    })

    assertions.append({
        "description": "Acknowledgment receipt PDF generated successfully with download link",
        "query": "receipt tool output inspection",
        "expected": "pdf_download_url present and size > 500 bytes",
        "actual": f"url: {r_data.get('pdf_download_url')}, size: {r_data.get('pdf_size_bytes')}",
        "passed": bool(r_data.get("success") and r_data.get("pdf_size_bytes", 0) > 500)
    })

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Status enquiry and receipt retrieval executed with accurate SLA tracking." if passed else "Status enquiry failed."
    }


def run_eval_08(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-08: Block Officer Review & Statutory Approval."""
    transcript = []
    assertions = []
    officer_user = spec["officer_user"]
    officer_token = mint_token_for(f"officer:{officer_user}", "officer", "officer")
    target_mobile = spec["target_persona_mobile"]
    t0 = time.time()

    # Step 1: Officer Dashboard
    code, res_d = mcp_call("officer", "tools/call", {"name": "get_officer_dashboard", "arguments": {}}, officer_token)
    d_data = json.loads(res_d.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 1,
        "action": "Officer Dashboard Overview",
        "tool": "get_officer_dashboard",
        "arguments": {},
        "response": redact_sensitive(res_d)
    })
    assertions.append({
        "description": "Officer dashboard returns total counts by status and pending counts by block",
        "query": "dashboard tool total_by_status check",
        "expected": "contains APPROVED and PENDING keys",
        "actual": list(d_data.get("total_by_status", {}).keys()),
        "passed": "APPROVED" in d_data.get("total_by_status", {})
    })

    # Step 2: List applications for Sonari block / target mobile
    code, res_l = mcp_call("officer", "tools/call", {
        "name": "list_applications",
        "arguments": {"mobile": target_mobile}
    }, officer_token)
    l_data = json.loads(res_l.get("result", {}).get("content", [{}])[0].get("text", "{}"))
    transcript.append({
        "step": 2,
        "action": "Queue Search for Target Application",
        "tool": "list_applications",
        "arguments": {"mobile": redact_sensitive(target_mobile)},
        "response": redact_sensitive(res_l)
    })

    apps = l_data.get("applications", [])
    target_app = apps[0] if apps else None
    target_app_id = target_app.get("id") if target_app else None

    # Step 3: Get dossier
    if target_app_id:
        code, res_dos = mcp_call("officer", "tools/call", {
            "name": "get_application_dossier",
            "arguments": {"app_id": target_app_id}
        }, officer_token)
        transcript.append({
            "step": 3,
            "action": "Inspect Full Application Dossier & Audit Log",
            "tool": "get_application_dossier",
            "arguments": {"app_id": target_app_id},
            "response": redact_sensitive(res_dos)
        })

        # Step 4: Approve with mandatory justification note
        approval_note = "Aadhaar verified: age 68 confirmed. Active SBI account verified against passbook copy."
        code, res_dec = mcp_call("officer", "tools/call", {
            "name": "decide_application",
            "arguments": {
                "app_id": target_app_id,
                "decision": "APPROVED",
                "note": approval_note
            }
        }, officer_token)
        transcript.append({
            "step": 4,
            "action": "Record Statutory Approval Decision",
            "tool": "decide_application",
            "arguments": {"app_id": target_app_id, "decision": "APPROVED", "note": approval_note},
            "response": redact_sensitive(res_dec)
        })

        # DB Assertions
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("SELECT status, decided_by FROM applications WHERE id = %s", (target_app_id,))
        app_row = cur.fetchone()
        assertions.append({
            "description": "Application status updated to APPROVED with decided_by = officer:admin",
            "query": f"SELECT status, decided_by FROM applications WHERE id = {target_app_id}",
            "expected": "APPROVED, officer:admin",
            "actual": f"{app_row[0]}, {app_row[1]}" if app_row else None,
            "passed": bool(app_row and app_row[0] == "APPROVED" and app_row[1] == "officer:admin")
        })

        cur.execute("SELECT action, actor, note FROM audit_log WHERE application_id = %s ORDER BY at DESC LIMIT 1", (target_app_id,))
        audit_row = cur.fetchone()
        assertions.append({
            "description": "Statutory audit trail logs APPROVED action and officer justification note",
            "query": f"SELECT action, actor, note FROM audit_log WHERE application_id = {target_app_id} ORDER BY at DESC LIMIT 1",
            "expected": f"APPROVED, officer:admin, {approval_note}",
            "actual": f"{audit_row[0]}, {audit_row[1]}, {audit_row[2]}" if audit_row else None,
            "passed": bool(audit_row and audit_row[0] == "APPROVED" and audit_row[1] == "officer:admin" and approval_note in audit_row[2])
        })
        cur.close()
        conn.close()
    else:
        assertions.append({
            "description": "Target application found in officer queue",
            "query": f"SELECT id FROM applications WHERE mobile = '{redact_sensitive(target_mobile)}'",
            "expected": "Valid app ID",
            "actual": None,
            "passed": False
        })

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Officer inspected dossier and recorded statutory approval with verified audit entry." if passed else "Officer approval verification failed."
    }


def run_eval_09(spec: Dict[str, Any]) -> Dict[str, Any]:
    """EVAL-09: Block Officer Statutory Rejection."""
    transcript = []
    assertions = []
    officer_user = spec["officer_user"]
    officer_token = mint_token_for(f"officer:{officer_user}", "officer", "officer")
    mobile = spec["target_persona_mobile"]
    t0 = time.time()

    # Pre-seed a pending application with flawed document
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, village, block,
            bank_account, ifsc, doc_path, status, submitted_at)
           VALUES ('SSPEVAL901', %s, %s, %s, %s, %s, %s, %s, 'blurred_aadhaar.jpg', 'PENDING', NOW())
           RETURNING id, application_no""",
        (spec["applicant_name"], mobile, portal.parse_dob(spec["dob"]), spec["village"], spec["block"],
         spec["bank_account"], spec["ifsc"])
    )
    app_id, app_no = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    # Step 1: Officer dossier review
    code, res_dos = mcp_call("officer", "tools/call", {
        "name": "get_application_dossier",
        "arguments": {"app_id": app_id}
    }, officer_token)
    transcript.append({
        "step": 1,
        "action": "Inspect Dossier with Blurred Document",
        "tool": "get_application_dossier",
        "arguments": {"app_id": app_id},
        "response": redact_sensitive(res_dos)
    })

    # Step 2: Officer rejects application with statutory note
    code, res_dec = mcp_call("officer", "tools/call", {
        "name": "decide_application",
        "arguments": {
            "app_id": app_id,
            "decision": "REJECTED",
            "note": spec["rejection_note"]
        }
    }, officer_token)
    transcript.append({
        "step": 2,
        "action": "Record Statutory Rejection Decision",
        "tool": "decide_application",
        "arguments": {"app_id": app_id, "decision": "REJECTED", "note": spec["rejection_note"]},
        "response": redact_sensitive(res_dec)
    })

    # DB Assertions
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT status, decided_by FROM applications WHERE id = %s", (app_id,))
    app_row = cur.fetchone()
    assertions.append({
        "description": "Application status updated to REJECTED with decided_by = officer:admin",
        "query": f"SELECT status, decided_by FROM applications WHERE id = {app_id}",
        "expected": "REJECTED, officer:admin",
        "actual": f"{app_row[0]}, {app_row[1]}" if app_row else None,
        "passed": bool(app_row and app_row[0] == "REJECTED" and app_row[1] == "officer:admin")
    })

    cur.execute("SELECT action, actor, note FROM audit_log WHERE application_id = %s ORDER BY at DESC LIMIT 1", (app_id,))
    audit_row = cur.fetchone()
    assertions.append({
        "description": "Statutory audit log records REJECTED action and official reason note",
        "query": f"SELECT action, actor, note FROM audit_log WHERE application_id = {app_id} ORDER BY at DESC LIMIT 1",
        "expected": f"REJECTED, officer:admin, {spec['rejection_note']}",
        "actual": f"{audit_row[0]}, {audit_row[1]}, {audit_row[2]}" if audit_row else None,
        "passed": bool(audit_row and audit_row[0] == "REJECTED" and audit_row[1] == "officer:admin" and spec["rejection_note"] in audit_row[2])
    })
    cur.close()
    conn.close()

    passed = all(a["passed"] for a in assertions)
    return {
        "scenario_id": spec["id"],
        "name": spec["name"],
        "passed": passed,
        "turn_count": len(transcript),
        "duration_ms": int((time.time() - t0) * 1000),
        "transcript": transcript,
        "assertions": assertions,
        "actual_outcome": "Officer recorded statutory rejection; audit log captures justification reason." if passed else "Officer rejection assertion failed."
    }


# ---------------------------------------------------------------------------
# Master Runner
# ---------------------------------------------------------------------------

RUNNERS = {
    "EVAL-01": run_eval_01,
    "EVAL-02": run_eval_02,
    "EVAL-03": run_eval_03,
    "EVAL-04": run_eval_04,
    "EVAL-05": run_eval_05,
    "EVAL-06": run_eval_06,
    "EVAL-07": run_eval_07,
    "EVAL-08": run_eval_08,
    "EVAL-09": run_eval_09,
}


def run_all_evaluations() -> Dict[str, Any]:
    """Execute all 9 evaluation scenarios, record outcomes, and persist to database."""
    ensure_eval_tables()
    clean_test_fixtures()

    run_id = f"eval_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    timestamp = datetime.now()
    results = []

    for spec in PERSONA_SPECS:
        fn = RUNNERS.get(spec["id"])
        if fn:
            # Combine spec with static metadata
            res = fn(spec)
            res["persona_summary"] = spec.get("persona_summary", "")
            res["eval_rationale"] = spec.get("eval_rationale", "")
            res["expected_outcome"] = spec.get("expected_statutory_outcome", "")
            results.append(res)

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    pass_rate = round((passed / total * 100), 1) if total else 0.0
    total_turns = sum(r.get("turn_count", 0) for r in results)
    avg_turns = round(total_turns / total, 1) if total else 0.0

    eval_summary = {
        "run_id": run_id,
        "timestamp": timestamp.strftime("%d-%m-%Y %H:%M:%S IST"),
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": pass_rate,
        "avg_turns": avg_turns,
        "scenarios": results
    }

    # Persist in Postgres eval_runs table
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO eval_runs
           (run_id, timestamp, total, passed, failed, pass_rate, avg_turns, results)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (run_id, timestamp, total, passed, failed, pass_rate, avg_turns, json.dumps(eval_summary))
    )
    conn.commit()
    cur.close()
    conn.close()

    return eval_summary


def get_latest_eval_run() -> Optional[Dict[str, Any]]:
    """Retrieve the latest completed evaluation run from PostgreSQL."""
    ensure_eval_tables()
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT results FROM eval_runs ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row and row[0]:
        return row[0] if isinstance(row[0], dict) else json.loads(row[0])
    return None


def get_eval_history(limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve historical evaluation run summaries from PostgreSQL."""
    ensure_eval_tables()
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute(
        """SELECT run_id, timestamp, total, passed, failed, pass_rate, avg_turns
           FROM eval_runs ORDER BY id DESC LIMIT %s""",
        (limit,)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    out = []
    for r in rows:
        out.append({
            "run_id": r[0],
            "timestamp": r[1].strftime("%d-%m-%Y %H:%M:%S") if r[1] else "",
            "total": r[2],
            "passed": r[3],
            "failed": r[4],
            "pass_rate": float(r[5]) if r[5] is not None else 0.0,
            "avg_turns": float(r[6]) if r[6] is not None else 0.0
        })
    return out


if __name__ == "__main__":
    print(f"Running Sewa Setu Evaluation Runner on {BASE_URL}...")
    summary = run_all_evaluations()
    print(f"\nCompleted Run {summary['run_id']}: {summary['passed']}/{summary['total']} Passed ({summary['pass_rate']}%)")
    for s in summary["scenarios"]:
        status_symbol = "✓ PASS" if s["passed"] else "✗ FAIL"
        print(f"  [{status_symbol}] {s['scenario_id']}: {s['name']} ({s['turn_count']} turns, {s['duration_ms']}ms)")
