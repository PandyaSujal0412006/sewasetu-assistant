# -*- coding: utf-8 -*-
"""
Automated Test Suite for Evaluation Runner and /eval-dashboard.

Tests:
  1. Full execution of all 9 required evaluation scenarios via eval_runner.
  2. 100% pass rate verification across all 9 scenarios.
  3. Strict database assertion checks (applications, portal_users, audit_log).
  4. Database volume and seed data protection (100k seed records intact).
  5. Repeated-run safety and idempotency.
  6. HTML Dashboard (/eval-dashboard) renders actual dynamic run data.
  7. JSON APIs (/eval-dashboard/api/latest, /eval-dashboard/api/history).
  8. Interactive re-run POST endpoint (/eval-dashboard/run).
  9. Sensitive data redaction verification.
"""

import os
import sys
import json
import unittest

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as portal
import eval_runner

BASE_URL = "http://127.0.0.1:8000"


class TestEvalDashboardAndRunner(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Count original non-test applications before running
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM applications WHERE mobile NOT LIKE '99900010%'")
        cls.baseline_seed_count = cur.fetchone()[0]
        cur.close()
        conn.close()

    def test_01_execute_all_9_evaluations(self):
        """Execute evaluation runner and verify all 9 scenarios pass."""
        summary = eval_runner.run_all_evaluations()

        self.assertEqual(summary["total"], 9)
        self.assertEqual(summary["passed"], 9)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["pass_rate"], 100.0)
        self.assertGreater(summary["avg_turns"], 1.0)
        self.assertEqual(len(summary["scenarios"]), 9)

        # Verify each specific scenario passed
        scenario_ids = [s["scenario_id"] for s in summary["scenarios"]]
        for expected_id in ["EVAL-01", "EVAL-02", "EVAL-03", "EVAL-04", "EVAL-05", "EVAL-06", "EVAL-07", "EVAL-08", "EVAL-09"]:
            self.assertIn(expected_id, scenario_ids)

        for s in summary["scenarios"]:
            self.assertTrue(s["passed"], f"Scenario {s['scenario_id']} failed: {s['actual_outcome']}")
            self.assertGreater(len(s["assertions"]), 0)
            self.assertTrue(all(a["passed"] for a in s["assertions"]))

    def test_02_database_seed_protection(self):
        """Ensure evaluation runner never mutates or deletes the 100k seed applications."""
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM applications WHERE mobile NOT LIKE '99900010%'")
        current_count = cur.fetchone()[0]
        cur.close()
        conn.close()

        self.assertEqual(
            current_count,
            self.baseline_seed_count,
            "Evaluation run mutated baseline seed records!"
        )

    def test_03_repeated_run_idempotency(self):
        """Running evaluations a second time must clean up previous test records and pass cleanly."""
        summary2 = eval_runner.run_all_evaluations()
        self.assertEqual(summary2["passed"], 9)
        self.assertEqual(summary2["failed"], 0)

        # Check total applications in test range is strictly bounded
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM applications WHERE mobile LIKE '99900010%'")
        test_app_count = cur.fetchone()[0]
        cur.close()
        conn.close()

        # Scenarios 1, 4, 5, 6, 7, 8, 9 produce applications; 2 and 3 do not.
        self.assertLessEqual(test_app_count, 10, "Uncontrolled duplicate test records created!")

    def test_04_eval_dashboard_html_view(self):
        """Verify /eval-dashboard route renders HTTP 200 with dynamic test details."""
        res = requests.get(f"{BASE_URL}/eval-dashboard")
        self.assertEqual(res.status_code, 200)
        content = res.text

        self.assertIn("AI &amp; MCP Evaluation Dashboard", content)
        self.assertIn("100", content)
        self.assertIn("EVAL-01", content)
        self.assertIn("Hemaprabha Saikia", content)
        self.assertIn("EVAL-08", content)
        self.assertIn("Statutory Approval", content)
        self.assertIn("Database Assertions", content)
        self.assertIn("Multi-Turn Tool Call Transcript", content)

    def test_05_eval_dashboard_json_apis(self):
        """Verify /eval-dashboard/api/latest and /history JSON endpoints."""
        res_latest = requests.get(f"{BASE_URL}/eval-dashboard/api/latest")
        self.assertEqual(res_latest.status_code, 200)
        data = res_latest.json()
        self.assertEqual(data["total"], 9)
        self.assertEqual(data["passed"], 9)
        self.assertEqual(data["pass_rate"], 100.0)

        res_hist = requests.get(f"{BASE_URL}/eval-dashboard/api/history")
        self.assertEqual(res_hist.status_code, 200)
        hist = res_hist.json()["history"]
        self.assertGreaterEqual(len(hist), 1)

    def test_06_interactive_rerun_endpoint(self):
        """Verify POST /eval-dashboard/run triggers a run and redirects back to dashboard."""
        res = requests.post(f"{BASE_URL}/eval-dashboard/run", allow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/eval-dashboard", res.headers.get("Location", ""))

    def test_07_sensitive_data_redaction(self):
        """Verify that transcripts and assertions do not leak full mobile numbers or tokens."""
        summary = eval_runner.get_latest_eval_run()
        summary_str = json.dumps(summary)

        # Check for unredacted JWT format: eyJ...
        self.assertNotIn("eyJhbGci", summary_str)
        # Check that test mobile numbers are masked
        self.assertNotIn("9990001001", summary_str)
        self.assertIn("999000****", summary_str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
