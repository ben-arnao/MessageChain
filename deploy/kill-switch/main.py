"""Billing kill switch for messagechain-validator.

Triggered by Pub/Sub messages from a Cloud Billing budget.  When actual
spend meets or exceeds the budget amount, unlinks the billing account
from the project — hard stop, not a throttle.  All running resources
(VMs, disks, etc.) will stop being chargeable and most will shut down.
Re-enable by linking the billing account back via the console or CLI.
"""

import base64
import json
import os

import functions_framework
from googleapiclient import discovery

PROJECT_ID = os.environ["TARGET_PROJECT_ID"]
PROJECT_NAME = f"projects/{PROJECT_ID}"


@functions_framework.cloud_event
def stop_billing(cloud_event):
    payload = base64.b64decode(cloud_event.data["message"]["data"]).decode("utf-8")
    alert = json.loads(payload)

    cost = float(alert.get("costAmount", 0))
    budget = float(alert.get("budgetAmount", 0))
    print(f"Budget alert: cost={cost} budget={budget} project={PROJECT_ID}")

    if cost < budget:
        print("Under budget — no action.")
        return

    billing = discovery.build("cloudbilling", "v1", cache_discovery=False)
    projects = billing.projects()

    info = projects.getBillingInfo(name=PROJECT_NAME).execute()
    if not info.get("billingEnabled", False):
        print("Billing already disabled.")
        return

    result = projects.updateBillingInfo(
        name=PROJECT_NAME, body={"billingAccountName": ""}
    ).execute()
    print(f"Billing disabled: {json.dumps(result)}")
