# -*- coding: utf-8 -*-
"""
Automated Integration Test Suite for Sewa Setu MCP Servers.

Tests:
  1. Tool isolation: citizen endpoint exposes only citizen tools; officer endpoint exposes only officer tools.
  2. Protocol compliance: initialize, tools/list, tools/call over JSON-RPC 2.0.
  3. Authentication enforcement: rejected with 401 without token.
  4. Cross-role boundary: citizen token rejected on officer endpoint; officer token rejected on citizen endpoint.
  5. Ineligible age: age 57 (<60) rejected by validation and submission.
  6. Unsupported block: block not in the 6 sanctioned blocks rejected.
  7. Malformed banking: invalid account (<9 digits) or invalid IFSC rejected with actionable errors.
  8. End-to-end citizen flow: upload document, validate draft, submit, track status, download receipt.
  9. Duplicate application prevention: second submission on active application blocked.
  10. Citizen withdrawal: pending application withdrawn cleanly.
  11. Officer workflow: dashboard metrics, queue listing, dossier inspection, statutory approval decision with note.
"""

import os
import sys
import json
import time
import unittest
from datetime import datetime, date

import requests
import jwt

# Add parent directory to path to access app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as portal
import oauth as portal_oauth


BASE_URL = "http://127.0.0.1:8000"


def get_token(subject: str, role: str, scope: str) -> str:
    """Helper to mint a valid RS256 token using the portal's internal key."""
    token, _ = portal_oauth.mint_access_token(
        subject=subject,
        role=role,
        scope=scope,
        audience=portal_oauth.ISSUER,
        client_id="test-harness",
        ttl=3600
    )
    return token


class TestSewaSetuMCPServers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.citizen_token = get_token("citizen:9876500001", "citizen", "citizen")
        cls.officer_token = get_token("officer:admin", "officer", "officer")
        cls.test_mobile = "9876500001"

        # Clean up any previous test applications for this test mobile
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_log WHERE actor = %s", (f"applicant:{cls.test_mobile}",))
        cur.execute("DELETE FROM applications WHERE mobile = %s", (cls.test_mobile,))
        cur.execute("DELETE FROM portal_users WHERE mobile = %s", (cls.test_mobile,))
        conn.commit()
        cur.close()
        conn.close()

    # -----------------------------------------------------------------------
    # 1. Tool Separation & Protocol Discovery
    # -----------------------------------------------------------------------

    def test_01_tool_separation(self):
        """Verify strict isolation of citizen and officer tools."""
        # Citizen tools list
        res_c = requests.post(
            f"{BASE_URL}/mcp/citizen",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        self.assertEqual(res_c.status_code, 200)
        citizen_tools = [t["name"] for t in res_c.json()["result"]["tools"]]

        # Officer tools list
        res_o = requests.post(
            f"{BASE_URL}/mcp/officer",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        )
        self.assertEqual(res_o.status_code, 200)
        officer_tools = [t["name"] for t in res_o.json()["result"]["tools"]]

        # Assert no overlap
        self.assertIn("submit_pension_application", citizen_tools)
        self.assertIn("get_scheme_guidelines", citizen_tools)
        self.assertNotIn("decide_application", citizen_tools)
        self.assertNotIn("get_officer_dashboard", citizen_tools)

        self.assertIn("decide_application", officer_tools)
        self.assertIn("get_officer_dashboard", officer_tools)
        self.assertNotIn("submit_pension_application", officer_tools)
        self.assertNotIn("withdraw_pension_application", officer_tools)

    def test_02_initialize_handshake(self):
        """Verify JSON-RPC 2.0 initialize handshake."""
        res = requests.post(
            f"{BASE_URL}/mcp/citizen",
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"}
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()["result"]
        self.assertEqual(data["serverInfo"]["name"], "sewasetu-citizen-mcp")
        self.assertEqual(data["protocolVersion"], "2024-11-05")

    # -----------------------------------------------------------------------
    # 2. Authentication & Role Enforcement
    # -----------------------------------------------------------------------

    def test_03_unauthorized_access(self):
        """Calling protected tools without a Bearer token must fail with 401."""
        res = requests.post(
            f"{BASE_URL}/mcp/citizen",
            json={
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {"name": "get_my_application_status", "arguments": {}}
            }
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("Unauthorized", res.json()["error"]["message"])

    def test_04_cross_role_access_blocked(self):
        """Citizen token must NOT be allowed to call officer tools, and vice versa."""
        # Citizen token accessing officer endpoint
        res_o = requests.post(
            f"{BASE_URL}/mcp/officer",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {"name": "get_officer_dashboard", "arguments": {}}
            }
        )
        self.assertEqual(res_o.status_code, 401)
        self.assertIn("Insufficient role", res_o.json()["error"]["message"])

        # Officer token accessing citizen endpoint
        res_c = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.officer_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {"name": "get_my_application_status", "arguments": {}}
            }
        )
        self.assertEqual(res_c.status_code, 401)
        self.assertIn("Insufficient role", res_c.json()["error"]["message"])

    # -----------------------------------------------------------------------
    # 3. Statutory Scheme Validations
    # -----------------------------------------------------------------------

    def test_05_ineligible_age_rejection(self):
        """Applicant under 60 years old must be rejected."""
        # DOB 15/05/1969 is under 60 in 2026 (age ~57)
        payload = {
            "applicant_name": "Ramen Barman",
            "village": "Borhat",
            "block": "Sonari",
            "dob": "15/05/1969",
            "bank_account": "123456789012",
            "ifsc": "SBIN0003077",
            "has_age_proof": True
        }
        res = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 40,
                "method": "tools/call",
                "params": {"name": "validate_application_draft", "arguments": payload}
            }
        )
        self.assertEqual(res.status_code, 200)
        output = json.loads(res.json()["result"]["content"][0]["text"])
        self.assertFalse(output["valid"])
        self.assertTrue(any("60 years of age or above" in err for err in output["errors"]))

    def test_06_unsupported_block_rejection(self):
        """Applicant from a non-sanctioned block must be rejected."""
        payload = {
            "applicant_name": "Pranab Saikia",
            "village": "Paltan Bazar",
            "block": "Guwahati Urban",
            "dob": "15/05/1954",
            "bank_account": "123456789012",
            "ifsc": "SBIN0003077",
            "has_age_proof": True
        }
        res = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 50,
                "method": "tools/call",
                "params": {"name": "validate_application_draft", "arguments": payload}
            }
        )
        self.assertEqual(res.status_code, 200)
        output = json.loads(res.json()["result"]["content"][0]["text"])
        self.assertFalse(output["valid"])
        self.assertTrue(any("block must be one of" in err for err in output["errors"]))

    def test_07_malformed_banking_data(self):
        """Invalid bank account digits or invalid IFSC must fail validation."""
        payload = {
            "applicant_name": "Hemaprabha Saikia",
            "village": "Borhat",
            "block": "Sonari",
            "dob": "15/05/1954",
            "bank_account": "12345",  # Under 9 digits
            "ifsc": "INVALID_IFSC",   # Malformed IFSC
            "has_age_proof": True
        }
        res = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 60,
                "method": "tools/call",
                "params": {"name": "validate_application_draft", "arguments": payload}
            }
        )
        self.assertEqual(res.status_code, 200)
        output = json.loads(res.json()["result"]["content"][0]["text"])
        self.assertFalse(output["valid"])
        self.assertTrue(any("bank account number must be 9 to 18 digits" in err for err in output["errors"]))
        self.assertTrue(any("IFSC must be 11 characters" in err for err in output["errors"]))

    # -----------------------------------------------------------------------
    # 4. End-to-End Citizen Application Flow
    # -----------------------------------------------------------------------

    def test_08_citizen_submission_and_status(self):
        """Upload proof, submit valid application, query status and download acknowledgment."""
        # 1. Upload age proof
        res_up = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 70,
                "method": "tools/call",
                "params": {
                    "name": "upload_age_proof_document",
                    "arguments": {"filename": "aadhaar_card.pdf", "document_type": "Aadhaar Card"}
                }
            }
        )
        self.assertEqual(res_up.status_code, 200)
        up_out = json.loads(res_up.json()["result"]["content"][0]["text"])
        self.assertTrue(up_out["success"])
        doc_path = up_out["doc_path"]

        # 2. Submit pension application (Age 72, Sonari block, valid bank/IFSC)
        submit_args = {
            "applicant_name": "Hemaprabha Saikia",
            "village": "Borhat Village",
            "block": "Sonari",
            "dob": "12/03/1954",
            "bank_account": "20485938491",
            "ifsc": "SBIN0003077",
            "doc_path": doc_path,
            "gender": "Female",
            "marital_status": "Widowed"
        }
        res_sub = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 71,
                "method": "tools/call",
                "params": {"name": "submit_pension_application", "arguments": submit_args}
            }
        )
        self.assertEqual(res_sub.status_code, 200)
        sub_out = json.loads(res_sub.json()["result"]["content"][0]["text"])
        self.assertTrue(sub_out["success"])
        app_no = sub_out["application_no"]
        self.assertTrue(app_no.startswith("SSP"))

        # 3. Check status via MCP
        res_stat = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 72,
                "method": "tools/call",
                "params": {"name": "get_my_application_status", "arguments": {}}
            }
        )
        self.assertEqual(res_stat.status_code, 200)
        stat_out = json.loads(res_stat.json()["result"]["content"][0]["text"])
        self.assertTrue(stat_out["has_application"])
        self.assertEqual(stat_out["application_no"], app_no)
        self.assertEqual(stat_out["status"], "PENDING")

        # 4. Check acknowledgment receipt
        res_ack = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 73,
                "method": "tools/call",
                "params": {"name": "get_acknowledgment_receipt", "arguments": {}}
            }
        )
        self.assertEqual(res_ack.status_code, 200)
        ack_out = json.loads(res_ack.json()["result"]["content"][0]["text"])
        self.assertTrue(ack_out["success"])
        self.assertEqual(ack_out["application_no"], app_no)
        self.assertGreater(ack_out["pdf_size_bytes"], 100)

    def test_09_duplicate_application_blocked(self):
        """Attempting to submit while another application is active must be blocked."""
        submit_args = {
            "applicant_name": "Hemaprabha Saikia",
            "village": "Borhat Village",
            "block": "Sonari",
            "dob": "12/03/1954",
            "bank_account": "20485938491",
            "ifsc": "SBIN0003077",
            "doc_path": "already_uploaded.pdf"
        }
        res = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 80,
                "method": "tools/call",
                "params": {"name": "submit_pension_application", "arguments": submit_args}
            }
        )
        self.assertEqual(res.status_code, 200)
        out = json.loads(res.json()["result"]["content"][0]["text"])
        self.assertFalse(out["success"])
        self.assertIn("already exists", out["error"])

    def test_10_withdrawal_and_reapplication(self):
        """Citizen can withdraw their pending application and submit again."""
        # 1. Withdraw
        res_w = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 90,
                "method": "tools/call",
                "params": {"name": "withdraw_pension_application", "arguments": {"reason": "Correcting IFSC code"}}
            }
        )
        self.assertEqual(res_w.status_code, 200)
        w_out = json.loads(res_w.json()["result"]["content"][0]["text"])
        self.assertTrue(w_out["success"])

        # 2. Verify status changed to WITHDRAWN
        res_stat = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 91,
                "method": "tools/call",
                "params": {"name": "get_my_application_status", "arguments": {}}
            }
        )
        stat_out = json.loads(res_stat.json()["result"]["content"][0]["text"])
        self.assertEqual(stat_out["status"], "WITHDRAWN")

        # 3. Submit afresh
        res_sub2 = requests.post(
            f"{BASE_URL}/mcp/citizen",
            headers={"Authorization": f"Bearer {self.citizen_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 92,
                "method": "tools/call",
                "params": {
                    "name": "submit_pension_application",
                    "arguments": {
                        "applicant_name": "Hemaprabha Saikia",
                        "village": "Borhat Village",
                        "block": "Sonari",
                        "dob": "12/03/1954",
                        "bank_account": "20485938491",
                        "ifsc": "SBIN0003077",
                        "doc_path": "reapplied_proof.pdf"
                    }
                }
            }
        )
        sub2_out = json.loads(res_sub2.json()["result"]["content"][0]["text"])
        self.assertTrue(sub2_out["success"])
        self.assertEqual(sub2_out["status"], "PENDING")

    # -----------------------------------------------------------------------
    # 5. Departmental Officer Workflow
    # -----------------------------------------------------------------------

    def test_11_officer_review_and_approval(self):
        """Officer gets dashboard, inspects dossier, and approves application."""
        # 1. Officer dashboard
        res_dash = requests.post(
            f"{BASE_URL}/mcp/officer",
            headers={"Authorization": f"Bearer {self.officer_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/call",
                "params": {"name": "get_officer_dashboard", "arguments": {}}
            }
        )
        self.assertEqual(res_dash.status_code, 200)
        dash_out = json.loads(res_dash.json()["result"]["content"][0]["text"])
        self.assertIn("total_by_status", dash_out)
        self.assertIn("pending_by_block", dash_out)

        # 2. List application queue for test mobile
        res_list = requests.post(
            f"{BASE_URL}/mcp/officer",
            headers={"Authorization": f"Bearer {self.officer_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 101,
                "method": "tools/call",
                "params": {"name": "list_applications", "arguments": {"mobile": self.test_mobile}}
            }
        )
        self.assertEqual(res_list.status_code, 200)
        list_out = json.loads(res_list.json()["result"]["content"][0]["text"])
        pending_apps = [a for a in list_out["applications"] if a["status"] == "PENDING"]
        self.assertGreaterEqual(len(pending_apps), 1)
        target_app = pending_apps[0]
        target_app_id = target_app["id"]

        # 3. Get application dossier
        res_dos = requests.post(
            f"{BASE_URL}/mcp/officer",
            headers={"Authorization": f"Bearer {self.officer_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 102,
                "method": "tools/call",
                "params": {"name": "get_application_dossier", "arguments": {"app_id": target_app_id}}
            }
        )
        self.assertEqual(res_dos.status_code, 200)
        dos_out = json.loads(res_dos.json()["result"]["content"][0]["text"])
        self.assertEqual(dos_out["id"], target_app_id)
        self.assertIn("audit_trail", dos_out)

        # 4. Decide application (Approve with statutory note)
        res_dec = requests.post(
            f"{BASE_URL}/mcp/officer",
            headers={"Authorization": f"Bearer {self.officer_token}"},
            json={
                "jsonrpc": "2.0",
                "id": 103,
                "method": "tools/call",
                "params": {
                    "name": "decide_application",
                    "arguments": {
                        "app_id": target_app_id,
                        "decision": "APPROVED",
                        "note": "Verified Age 72 against Aadhaar and confirmed active SBI account."
                    }
                }
            }
        )
        self.assertEqual(res_dec.status_code, 200)
        dec_out = json.loads(res_dec.json()["result"]["content"][0]["text"])
        self.assertTrue(dec_out["success"])
        self.assertEqual(dec_out["status"], "APPROVED")

        # 5. Verify database reflection
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("SELECT status, decided_by FROM applications WHERE id = %s", (target_app_id,))
        db_row = cur.fetchone()
        self.assertEqual(db_row[0], "APPROVED")
        self.assertEqual(db_row[1], "officer:admin")

        cur.execute("SELECT action, actor, note FROM audit_log WHERE application_id = %s ORDER BY at DESC LIMIT 1", (target_app_id,))
        audit_row = cur.fetchone()
        self.assertEqual(audit_row[0], "APPROVED")
        self.assertEqual(audit_row[1], "officer:admin")
        self.assertIn("Verified Age 72", audit_row[2])
        cur.close()
        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
