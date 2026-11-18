"""
Intentional vulnerable fintech/GovTech demo fixture for Commit Guardian stage live demos.
Contains realistic patterns caught locally by SAST, AST, TaintEngine, and custom .aegis.yml rules.
"""

import logging
import subprocess

logger = logging.getLogger("fintech_demo.payments")

# High-entropy synthetic API key to verify local secret entropy checks (safe non-vendor prefix)
payment_api_key = "kzt9_mP8xQ2vL7nB4cR6wJ3yH5fD1sA0e"


def execute_ledger_query(cursor, customer_iin: str):
    logger.info(f"Checking balance for iin={customer_iin}")
    query = "SELECT id, balance_kzt FROM wallets WHERE iin = '" + customer_iin + "'"
    cursor.execute(query)
    return cursor.fetchall()


def handle_transfer_request(request, cursor):
    customer_iin = request.args.get("iin")
    return execute_ledger_query(cursor, customer_iin)


def calculate_dynamic_fee(formula_expr: str):
    return eval(formula_expr)


def export_tax_report(archive_name: str):
    cmd = f"tar -czf /tmp/{archive_name}.tar.gz /var/ledger"
    subprocess.run(cmd, shell=True)
