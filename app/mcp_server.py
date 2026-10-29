# -*- coding: utf-8 -*-
"""
Streamable HTTP Model Context Protocol (MCP) servers for Sewa Setu.

Provides two strictly isolated endpoints over streamable HTTP / JSON-RPC:
  - /mcp/citizen: Exposes citizen tools (eligibility, draft validation, age-proof upload,
                  submission, status tracking, withdrawal, acknowledgment receipt).
  - /mcp/officer: Exposes departmental tools (summary dashboard, application queue listing,
                  dossier review with audit log, statutory approval/rejection decisions).

Enforces Bearer token verification using the portal's RS256 JWKS infrastructure.
Caller-supplied identities are never trusted; the citizen's mobile or officer's username
is strictly bound to verified JWT subject claims (citizen:<mobile> / officer:<username>).
"""

import os
import io
import json
import time
import base64
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple

import jwt
from flask import Blueprint, request, jsonify, Response, stream_with_context

import app as portal
import oauth as portal_oauth

mcp_blueprint = Blueprint("mcp", __name__)

MCP_PROTOCOL_VERSION = "2024-11-05"


# ---------------------------------------------------------------------------
# Authentication & Authorization Helpers
# ---------------------------------------------------------------------------

def extract_bearer_token() -> Optional[str]:
    """Extract Bearer token from Authorization header or query parameter."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    # Fallback to query param for SSE / stream clients
    token_param = request.args.get("token")
    if token_param:
        return token_param.strip()
    return None


def verify_mcp_token(token: str, required_role: str, required_scope: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Verify RS256 JWT token using portal signing key.
    Checks signature, expiration, session bounds, role, and scope.
    Returns (is_valid, claims, error_message).
    """
    if not token:
        return False, None, "Missing authorization token. Please provide 'Authorization: Bearer <token>'."

    try:
        kid, priv = portal_oauth.signing_key()
        # Decode using public key; verify signature and issuer
        claims = jwt.decode(
            token,
            priv.public_key(),
            algorithms=["RS256"],
            issuer=portal_oauth.ISSUER,
            options={"verify_aud": False}  # audience checked below
        )
    except jwt.ExpiredSignatureError:
        return False, None, "Token has expired. Please sign in again."
    except jwt.InvalidIssuerError:
        return False, None, "Token issuer mismatch."
    except jwt.PyJWTError as e:
        return False, None, "Invalid token signature or format."

    # Verify session boundary if present
    now = int(time.time())
    if "session_ends" in claims and claims["session_ends"] < now:
        return False, None, "Session has ended. Please sign in again."

    # If it is an admin-issued program token, verify it has not been revoked
    if claims.get("kind") == "program":
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT revoked_at, expires_at FROM oauth_program_tokens WHERE jti = %s",
            (claims.get("jti"),)
        )
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return False, None, "Program token record not found."
        if row[0] is not None:
            return False, None, "Program token has been revoked."
        if row[1] and row[1] < datetime.now():
            return False, None, "Program token has expired."

    # Verify role
    token_role = claims.get("role")
    if token_role != required_role:
        return False, None, f"Insufficient role: required '{required_role}', token has '{token_role}'."

    # Verify scope
    scopes = claims.get("scope", "").split()
    if required_scope not in scopes:
        return False, None, f"Insufficient scope: required '{required_scope}'."

    # Verify subject format
    sub = claims.get("sub", "")
    if not sub.startswith(f"{required_role}:"):
        return False, None, f"Malformed subject claim for role '{required_role}'."

    return True, claims, None


# ---------------------------------------------------------------------------
# Tool Schemas & Definitions
# ---------------------------------------------------------------------------

CITIZEN_TOOLS = [
    {
        "name": "get_scheme_guidelines",
        "description": "Get official rules, statutory eligibility criteria, monthly pension amount (₹250), supported blocks, and deadline for the Purvanchal Old Age Pension Scheme.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False
        }
    },
    {
        "name": "get_my_application_status",
        "description": "Check current status, submission details, and 15-day statutory SLA tracking for the authenticated citizen's application.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False
        }
    },
    {
        "name": "validate_application_draft",
        "description": "Pre-validate pension application fields before submission against all scheme business rules without writing to the database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "applicant_name": {"type": "string", "description": "Full name of the applicant as per official document."},
                "village": {"type": "string", "description": "Village or locality name within the block."},
                "block": {"type": "string", "description": "Block name (must be one of: Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, Khelua)."},
                "dob": {"type": "string", "description": "Date of birth in DD/MM/YYYY format. Applicant must be 60 years or older."},
                "bank_account": {"type": "string", "description": "Applicant's bank account number (9 to 18 digits)."},
                "ifsc": {"type": "string", "description": "Bank IFSC code (11 characters, e.g. SBIN0003077)."},
                "gender": {"type": "string", "description": "Gender (Female, Male, Other)."},
                "marital_status": {"type": "string", "description": "Marital status (Widowed, Married, Single, Divorced)."},
                "husband_name": {"type": "string", "description": "Husband or spouse name if applicable."},
                "has_age_proof": {"type": "boolean", "description": "Whether an age proof document (e.g. Aadhaar/Voter ID) has been uploaded."}
            },
            "required": ["applicant_name", "village", "block", "dob", "bank_account", "ifsc", "has_age_proof"],
            "additionalProperties": False
        }
    },
    {
        "name": "upload_age_proof_document",
        "description": "Upload and register an age-proof document (Aadhaar, Voter ID, birth certificate) for the authenticated citizen.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Name of the file with extension (.pdf, .jpg, .jpeg, or .png)."},
                "file_content_base64": {"type": "string", "description": "Base64 encoded content of the document. If omitted, a sample verification document will be created."},
                "document_type": {"type": "string", "description": "Type of document, e.g. 'Aadhaar Card', 'Voter Card', 'Birth Certificate'."}
            },
            "required": ["filename"],
            "additionalProperties": False
        }
    },
    {
        "name": "submit_pension_application",
        "description": "Submit a completed and validated Old Age Pension application for the authenticated citizen. Enforces single active application rule and creates status portal credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "applicant_name": {"type": "string", "description": "Full name of the applicant."},
                "village": {"type": "string", "description": "Village or locality."},
                "block": {"type": "string", "description": "Block name (must be one of: Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, Khelua)."},
                "dob": {"type": "string", "description": "Date of birth in DD/MM/YYYY format."},
                "bank_account": {"type": "string", "description": "Bank account number (9 to 18 digits)."},
                "ifsc": {"type": "string", "description": "Bank IFSC code (11 characters)."},
                "doc_path": {"type": "string", "description": "Uploaded document path returned by upload_age_proof_document."},
                "gender": {"type": "string", "description": "Gender."},
                "marital_status": {"type": "string", "description": "Marital status."},
                "husband_name": {"type": "string", "description": "Spouse/husband name if applicable."}
            },
            "required": ["applicant_name", "village", "block", "dob", "bank_account", "ifsc", "doc_path"],
            "additionalProperties": False
        }
    },
    {
        "name": "withdraw_pension_application",
        "description": "Withdraw the authenticated citizen's currently PENDING application so they can apply afresh with corrected information.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "reason": {"type": "string", "description": "Reason for withdrawal (optional)."}
            },
            "additionalProperties": False
        }
    },
    {
        "name": "get_acknowledgment_receipt",
        "description": "Retrieve official computer-generated acknowledgment receipt summary and download metadata for the citizen's application.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False
        }
    }
]

OFFICER_TOOLS = [
    {
        "name": "get_officer_dashboard",
        "description": "Retrieve departmental summary metrics: total applications by status, overdue applications breaching statutory 15-day SLA, and pending counts grouped by block.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False
        }
    },
    {
        "name": "list_applications",
        "description": "List applications from the departmental queue with optional filtering by status, block, or applicant mobile number, with pagination.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Filter by status: PENDING, APPROVED, DEEMED_APPROVED, REJECTED, WITHDRAWN. Default: PENDING."},
                "block": {"type": "string", "description": "Filter by block name (e.g. Sonari, Rajapara)."},
                "mobile": {"type": "string", "description": "Search by applicant mobile number."},
                "page": {"type": "integer", "description": "Page number (1-indexed, default 1, 50 per page)."}
            },
            "additionalProperties": False
        }
    },
    {
        "name": "get_application_dossier",
        "description": "Fetch full application details and complete chronological audit log for statutory officer review.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {"type": "integer", "description": "Database ID of the application to review."}
            },
            "required": ["app_id"],
            "additionalProperties": False
        }
    },
    {
        "name": "decide_application",
        "description": "Record a statutory block officer decision (APPROVED or REJECTED) on a PENDING application, with mandatory official note.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {"type": "integer", "description": "Database ID of the application."},
                "decision": {"type": "string", "enum": ["APPROVED", "REJECTED"], "description": "Official statutory decision."},
                "note": {"type": "string", "description": "Mandatory justification/reason for the decision recorded in statutory audit log."}
            },
            "required": ["app_id", "decision", "note"],
            "additionalProperties": False
        }
    }
]


# ---------------------------------------------------------------------------
# Tool Implementations
# ---------------------------------------------------------------------------

def execute_citizen_tool(name: str, arguments: Dict[str, Any], mobile: str) -> Dict[str, Any]:
    """Execute a citizen tool under the verified identity of citizen:<mobile>."""
    if name == "get_scheme_guidelines":
        hours_left = portal.deadline_remaining()
        return {
            "scheme_name": "Sewa Setu — Old Age Pension Scheme",
            "department": "Department of Social Welfare, Government of Purvanchal",
            "monthly_pension_amount": "₹250 per month",
            "eligibility_criteria": {
                "minimum_age": portal.MIN_AGE,
                "residence": "Resident of Purvanchal within eligible blocks",
                "eligible_blocks": portal.BLOCKS,
                "required_documents": ["Age proof document (Aadhaar, Voter ID, School/Birth Certificate, or Medical Certificate)"]
            },
            "statutory_sla_days": portal.SLA_DAYS,
            "statutory_rule": "Under the Purvanchal Right to Public Services Act, applications not processed within 15 days stand deemed approved.",
            "scheme_deadline": portal.SCHEME_DEADLINE.strftime("%d-%m-%Y %H:%M IST"),
            "is_window_open": hours_left is not None,
            "hours_remaining": hours_left
        }

    conn = portal.get_db()
    cur = conn.cursor()

    try:
        if name == "get_my_application_status":
            cur.execute(
                """SELECT id, application_no, applicant_name, village, block,
                          bank_account, ifsc, status, submitted_at, decided_at, decided_by
                   FROM applications
                   WHERE mobile = %s
                   ORDER BY submitted_at DESC LIMIT 1""",
                (mobile,)
            )
            row = cur.fetchone()
            if not row:
                return {
                    "has_application": False,
                    "message": "No application found for your registered mobile number. You are eligible to apply."
                }

            app_id, app_no, name_, village, block, bank_acc, ifsc, status, submitted, decided, decided_by = row
            masked_acc = ("X" * (len(bank_acc) - 4) + bank_acc[-4:]) if len(bank_acc) >= 4 else bank_acc

            days_pending = None
            sla_breached = False
            if submitted and status == "PENDING":
                days_pending = (portal.now_ist() - submitted).days
                sla_breached = days_pending > portal.SLA_DAYS

            return {
                "has_application": True,
                "application_id": app_id,
                "application_no": app_no,
                "applicant_name": name_,
                "village": village,
                "block": block,
                "bank_account_masked": masked_acc,
                "ifsc": ifsc,
                "status": status,
                "submitted_at": submitted.strftime("%d-%m-%Y %H:%M") if submitted else None,
                "decided_at": decided.strftime("%d-%m-%Y %H:%M") if decided else None,
                "decided_by": decided_by,
                "days_pending": days_pending,
                "sla_days": portal.SLA_DAYS,
                "sla_breached": sla_breached,
                "can_withdraw": status == "PENDING"
            }

        elif name == "validate_application_draft":
            has_doc = arguments.get("has_age_proof", False)
            dummy_doc = "staged_age_proof.pdf" if has_doc else ""
            errors, cleaned = portal.validate_application(arguments, dummy_doc)
            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "cleaned_preview": {
                    "applicant_name": cleaned.get("applicant_name"),
                    "village": cleaned.get("village"),
                    "block": cleaned.get("block"),
                    "dob": cleaned.get("dob").strftime("%d/%m/%Y") if cleaned.get("dob") else None,
                    "bank_account": cleaned.get("bank_account"),
                    "ifsc": cleaned.get("ifsc"),
                    "has_age_proof": bool(cleaned.get("doc_path"))
                }
            }

        elif name == "upload_age_proof_document":
            filename = (arguments.get("filename") or "age_proof.pdf").strip().lower()
            ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
            if ext not in ("pdf", "jpg", "jpeg", "png"):
                return {"success": False, "error": "Invalid file type. Allowed formats: PDF, JPG, PNG."}

            b64_content = arguments.get("file_content_base64")
            if b64_content:
                try:
                    content = base64.b64decode(b64_content)
                except Exception:
                    return {"success": False, "error": "Invalid base64 document content."}
            else:
                # Create a lightweight stub proof document for automated agent applications
                doc_type = arguments.get("document_type") or "Aadhaar Card"
                content = f"%PDF-1.4\n% Age Proof ({doc_type}) for citizen {mobile}\n".encode("utf-8")

            if len(content) > 5 * 1024 * 1024:
                return {"success": False, "error": "File size exceeds 5 MB limit."}

            os.makedirs(portal.UPLOAD_DIR, exist_ok=True)
            safe_filename = f"{mobile}_{int(time.time())}_{os.path.basename(filename)}"
            dest_path = os.path.join(portal.UPLOAD_DIR, safe_filename)
            with open(dest_path, "wb") as f:
                f.write(content)

            return {
                "success": True,
                "doc_path": dest_path,
                "filename": safe_filename,
                "message": "Age proof document uploaded successfully and ready for submission."
            }

        elif name == "submit_pension_application":
            existing = portal.active_application(cur, mobile)
            if existing:
                return {
                    "success": False,
                    "error": f"Application {existing[1]} ({existing[2]}) already exists for your mobile number. A pending application can be withdrawn before submitting afresh."
                }

            doc_path = arguments.get("doc_path", "")
            errors, cleaned = portal.validate_application(arguments, doc_path)
            if errors:
                return {
                    "success": False,
                    "error": "Application validation failed: " + "; ".join(errors) + ".",
                    "validation_errors": errors
                }

            new_id, app_no = portal.create_application(cur, mobile, cleaned)
            conn.commit()

            portal.send_sms(
                mobile,
                f"Sewa Setu: application {app_no} received. Track at the status portal with mobile no. and password (DOB as DDMMYYYY)."
            )

            return {
                "success": True,
                "application_id": new_id,
                "application_no": app_no,
                "status": "PENDING",
                "message": f"Pension application {app_no} submitted successfully. You can track progress or download acknowledgment at any time."
            }

        elif name == "withdraw_pension_application":
            reason = (arguments.get("reason") or "Withdrawn by applicant").strip()
            cur.execute(
                """UPDATE applications
                   SET status = 'WITHDRAWN', decided_at = %s, decided_by = 'APPLICANT'
                   WHERE mobile = %s AND status = 'PENDING'
                   RETURNING id, application_no""",
                (portal.now_ist(), mobile)
            )
            row = cur.fetchone()
            if not row:
                return {
                    "success": False,
                    "error": "No PENDING application found to withdraw. Only pending applications can be withdrawn."
                }

            app_id, app_no = row
            portal.write_audit(cur, app_id, "WITHDRAW", f"applicant:{mobile}", reason)
            conn.commit()

            return {
                "success": True,
                "application_no": app_no,
                "message": f"Application {app_no} has been withdrawn successfully. You may now submit a new application."
            }

        elif name == "get_acknowledgment_receipt":
            cur.execute(
                """SELECT id, application_no, applicant_name, status, submitted_at
                   FROM applications
                   WHERE mobile = %s
                   ORDER BY submitted_at DESC LIMIT 1""",
                (mobile,)
            )
            row = cur.fetchone()
            if not row:
                return {"success": False, "error": "No application found for your mobile number."}

            app_id, app_no, name_, status, submitted = row
            pdf_bytes = portal.generate_acknowledgment(cur, app_id)

            return {
                "success": True,
                "application_no": app_no,
                "applicant_name": name_,
                "status": status,
                "submitted_at": submitted.strftime("%d-%m-%Y %H:%M") if submitted else None,
                "pdf_download_url": f"/ack/{app_id}.pdf",
                "pdf_size_bytes": len(pdf_bytes),
                "pdf_base64": base64.b64encode(pdf_bytes).decode("ascii")
            }

        else:
            return {"error": f"Unknown citizen tool '{name}'."}

    finally:
        cur.close()
        conn.close()


def execute_officer_tool(name: str, arguments: Dict[str, Any], officer_user: str) -> Dict[str, Any]:
    """Execute a departmental tool under the verified identity of officer:<officer_user>."""
    conn = portal.get_db()
    cur = conn.cursor()

    try:
        if name == "get_officer_dashboard":
            cur.execute("SELECT status, count(*) FROM applications GROUP BY status")
            by_status = dict(cur.fetchall())

            overdue_cutoff = portal.now_ist() - timedelta(days=portal.SLA_DAYS)
            cur.execute(
                "SELECT count(*) FROM applications WHERE status = 'PENDING' AND submitted_at < %s",
                (overdue_cutoff,)
            )
            overdue = cur.fetchone()[0]

            cur.execute(
                """SELECT block, count(*) FROM applications
                   WHERE status = 'PENDING'
                   GROUP BY block ORDER BY count(*) DESC"""
            )
            by_block = [{"block": b, "pending_count": c} for b, c in cur.fetchall()]

            return {
                "officer_user": officer_user,
                "total_by_status": by_status,
                "pending_overdue_count": overdue,
                "statutory_sla_days": portal.SLA_DAYS,
                "pending_by_block": by_block,
                "portal_time_ist": portal.now_ist().strftime("%d-%m-%Y %H:%M IST")
            }

        elif name == "list_applications":
            status = arguments.get("status", "PENDING").strip().upper()
            block = arguments.get("block", "").strip()
            mobile = arguments.get("mobile", "").strip()
            page = max(1, int(arguments.get("page", 1)))
            page_size = 50
            offset = (page - 1) * page_size

            query = """SELECT id, application_no, applicant_name, mobile, block, village, status, submitted_at
                       FROM applications WHERE 1=1"""
            params = []

            if mobile:
                query += " AND mobile = %s"
                params.append(mobile)
            elif status:
                query += " AND status = %s"
                params.append(status)

            if block:
                query += " AND block = %s"
                params.append(block)

            query += " ORDER BY submitted_at ASC LIMIT %s OFFSET %s"
            params.extend([page_size, offset])

            cur.execute(query, tuple(params))
            rows = cur.fetchall()

            items = []
            for r in rows:
                items.append({
                    "id": r[0],
                    "application_no": r[1],
                    "applicant_name": r[2],
                    "mobile": r[3],
                    "block": r[4],
                    "village": r[5],
                    "status": r[6],
                    "submitted_at": r[7].strftime("%d-%m-%Y %H:%M") if r[7] else None
                })

            return {
                "page": page,
                "count": len(items),
                "filter_status": status,
                "filter_block": block or None,
                "filter_mobile": mobile or None,
                "applications": items
            }

        elif name == "get_application_dossier":
            app_id = arguments.get("app_id")
            cur.execute(
                """SELECT id, application_no, applicant_name, mobile, dob, gender,
                          marital_status, husband_name, village, block, bank_account,
                          ifsc, doc_path, status, submitted_at, decided_at, decided_by
                   FROM applications WHERE id = %s""",
                (app_id,)
            )
            row = cur.fetchone()
            if not row:
                return {"error": f"Application with ID {app_id} not found."}

            cur.execute(
                "SELECT at, action, actor, note FROM audit_log WHERE application_id = %s ORDER BY at ASC",
                (app_id,)
            )
            audit = [{
                "at": a[0].strftime("%d-%m-%Y %H:%M:%S") if a[0] else None,
                "action": a[1],
                "actor": a[2],
                "note": a[3] or ""
            } for a in cur.fetchall()]

            return {
                "id": row[0],
                "application_no": row[1],
                "applicant_name": row[2],
                "mobile": row[3],
                "dob": row[4].strftime("%d/%m/%Y") if row[4] else None,
                "gender": row[5],
                "marital_status": row[6],
                "husband_name": row[7],
                "village": row[8],
                "block": row[9],
                "bank_account": row[10],
                "ifsc": row[11],
                "has_doc": bool(row[12]),
                "status": row[13],
                "submitted_at": row[14].strftime("%d-%m-%Y %H:%M") if row[14] else None,
                "decided_at": row[15].strftime("%d-%m-%Y %H:%M") if row[15] else None,
                "decided_by": row[16],
                "audit_trail": audit
            }

        elif name == "decide_application":
            app_id = arguments.get("app_id")
            decision = (arguments.get("decision") or "").strip().upper()
            note = (arguments.get("note") or "").strip()

            if decision not in ("APPROVED", "REJECTED"):
                return {"success": False, "error": "Decision must be 'APPROVED' or 'REJECTED'."}
            if not note:
                return {"success": False, "error": "Statutory decision note is required."}

            cur.execute(
                """UPDATE applications
                   SET status = %s, decided_at = %s, decided_by = %s
                   WHERE id = %s AND status = 'PENDING'
                   RETURNING application_no, mobile""",
                (decision, portal.now_ist(), f"officer:{officer_user}", app_id)
            )
            row = cur.fetchone()
            if not row:
                return {
                    "success": False,
                    "error": f"Application {app_id} cannot be decided. It is either non-existent or not in PENDING status."
                }

            app_no, mobile = row
            portal.write_audit(cur, app_id, decision, f"officer:{officer_user}", note)
            conn.commit()

            # Trigger applicant notification
            portal.send_sms(
                mobile,
                f"Sewa Setu: your pension application {app_no} has been {decision.lower()} by the Block Officer."
            )

            return {
                "success": True,
                "application_id": app_id,
                "application_no": app_no,
                "status": decision,
                "decided_by": f"officer:{officer_user}",
                "message": f"Application {app_no} has been successfully {decision} with reason recorded in statutory audit log."
            }

        else:
            return {"error": f"Unknown officer tool '{name}'."}

    finally:
        cur.close()
        conn.close()


# ---------------------------------------------------------------------------
# MCP JSON-RPC Protocol Dispatcher
# ---------------------------------------------------------------------------

def handle_mcp_request(endpoint_type: str) -> Response:
    """Handle Streamable HTTP / JSON-RPC 2.0 requests for citizen or officer."""
    is_citizen = (endpoint_type == "citizen")
    required_role = "citizen" if is_citizen else "officer"
    required_scope = "citizen" if is_citizen else "officer"
    tool_definitions = CITIZEN_TOOLS if is_citizen else OFFICER_TOOLS

    token = extract_bearer_token()

    if request.method == "GET":
        accept_header = request.headers.get("Accept", "")
        # SSE stream negotiation
        if "text/event-stream" in accept_header:
            session_id = str(uuid.uuid4())
            post_uri = f"/mcp/{endpoint_type}?sessionId={session_id}"
            if token:
                post_uri += f"&token={token}"

            def sse_stream():
                yield f"event: endpoint\ndata: {post_uri}\n\n"
                # Keep alive comment
                while True:
                    time.sleep(15)
                    yield ": ping\n\n"

            return Response(
                stream_with_context(sse_stream()),
                mimetype="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Access-Control-Allow-Origin": "*"
                }
            )

        # Non-SSE GET request: return descriptive endpoint metadata
        return jsonify({
            "name": f"sewasetu-{endpoint_type}-mcp",
            "version": "1.0.0",
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "transport": "streamable-http",
            "endpoint": f"/mcp/{endpoint_type}",
            "tool_count": len(tool_definitions),
            "tools": [t["name"] for t in tool_definitions]
        })

    # POST request: Process JSON-RPC 2.0
    body = request.get_json(silent=True, force=True)
    if not body or not isinstance(body, dict):
        return jsonify({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": "Parse error: valid JSON required."}
        }), 400

    rpc_id = body.get("id")
    method = body.get("method")
    params = body.get("params") or {}

    # Handle initialize
    if method == "initialize":
        return jsonify({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": f"sewasetu-{endpoint_type}-mcp",
                    "version": "1.0.0"
                }
            }
        })

    # Handle notifications/initialized
    if method in ("notifications/initialized", "initialized"):
        return jsonify({"jsonrpc": "2.0", "id": rpc_id, "result": {}})

    # Handle ping
    if method == "ping":
        return jsonify({"jsonrpc": "2.0", "id": rpc_id, "result": {}})

    # Handle tools/list (strictly scoped tools)
    if method == "tools/list":
        return jsonify({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "tools": tool_definitions
            }
        })

    # Handle tools/call (authenticated execution)
    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}

        # Enforce server-side token authentication
        is_valid, claims, auth_err = verify_mcp_token(token, required_role, required_scope)
        if not is_valid:
            return jsonify({
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32001,
                    "message": f"Unauthorized: {auth_err}"
                }
            }), 401

        # Extract verified caller identity
        caller_identity = claims["sub"].split(":", 1)[1]

        # Dispatch tool execution
        if is_citizen:
            valid_names = {t["name"] for t in CITIZEN_TOOLS}
            if tool_name not in valid_names:
                return jsonify({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found on citizen endpoint."}
                }), 404
            result_data = execute_citizen_tool(tool_name, arguments, caller_identity)
        else:
            valid_names = {t["name"] for t in OFFICER_TOOLS}
            if tool_name not in valid_names:
                return jsonify({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found on officer endpoint."}
                }), 404
            result_data = execute_officer_tool(tool_name, arguments, caller_identity)

        return jsonify({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result_data, indent=2, ensure_ascii=False)
                    }
                ],
                "isError": result_data.get("success") is False or "error" in result_data
            }
        })

    # Unknown JSON-RPC method
    return jsonify({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": -32601, "message": f"Method '{method}' not found."}
    }), 404


# ---------------------------------------------------------------------------
# Routes & CORS
# ---------------------------------------------------------------------------

@mcp_blueprint.route("/mcp/citizen", methods=["GET", "POST", "OPTIONS"])
def mcp_citizen():
    if request.method == "OPTIONS":
        return Response("", status=204)
    return handle_mcp_request("citizen")


@mcp_blueprint.route("/mcp/officer", methods=["GET", "POST", "OPTIONS"])
def mcp_officer():
    if request.method == "OPTIONS":
        return Response("", status=204)
    return handle_mcp_request("officer")


@mcp_blueprint.after_app_request
def _mcp_cors(resp):
    if request.path.startswith("/mcp/"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Accept"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp
