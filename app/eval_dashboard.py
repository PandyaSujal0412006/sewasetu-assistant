# -*- coding: utf-8 -*-
"""
Interactive Evaluation Dashboard for Sewa Setu Old Age Pension Portal.

Routes:
  - GET  /eval-dashboard: Renders interactive evaluation report, personas,
                          multi-turn transcripts, and database assertion tables.
  - POST /eval-dashboard/run: Executes fresh evaluation run on demand.
  - GET  /eval-dashboard/api/latest: JSON endpoint returning latest evaluation report.
  - GET  /eval-dashboard/api/history: JSON endpoint returning evaluation run history.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
import eval_runner

eval_dashboard_blueprint = Blueprint("eval_dashboard", __name__)


@eval_dashboard_blueprint.route("/eval-dashboard", methods=["GET"])
def dashboard_view():
    latest_run = eval_runner.get_latest_eval_run()
    history = eval_runner.get_eval_history(limit=10)
    return render_template("eval_dashboard.html", latest=latest_run, history=history)


@eval_dashboard_blueprint.route("/eval-dashboard/run", methods=["POST"])
def trigger_eval():
    try:
        summary = eval_runner.run_all_evaluations()
        flash(f"Evaluation Run {summary['run_id']} completed: {summary['passed']}/{summary['total']} passed ({summary['pass_rate']}%).")
    except Exception as e:
        flash(f"Error executing evaluation suite: {e}")
    return redirect(url_for("eval_dashboard.dashboard_view"))


@eval_dashboard_blueprint.route("/eval-dashboard/api/latest", methods=["GET"])
def api_latest():
    latest_run = eval_runner.get_latest_eval_run()
    if not latest_run:
        return jsonify({"status": "no_runs_yet", "message": "No evaluations have been run yet."}), 404
    return jsonify(latest_run)


@eval_dashboard_blueprint.route("/eval-dashboard/api/history", methods=["GET"])
def api_history():
    history = eval_runner.get_eval_history(limit=20)
    return jsonify({"history": history})
