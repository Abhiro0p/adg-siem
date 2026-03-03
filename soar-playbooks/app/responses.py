from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from .drivers.cisco_ise import quarantine_mac
from .drivers.crowdstrike import isolate_device as cs_isolate
from .drivers.defender import isolate_device as defender_isolate
from .models import Alert

logger = logging.getLogger("adg.soar.responses")


class ResponseActions:
    def __init__(
        self,
        output_dir: str = "./state",
        # EDR
        defender_url: Optional[str] = None,
        defender_token: Optional[str] = None,
        crowdstrike_url: Optional[str] = None,
        crowdstrike_token: Optional[str] = None,
        sentinelone_url: Optional[str] = None,
        sentinelone_token: Optional[str] = None,
        # NAC
        ise_url: Optional[str] = None,
        ise_user: Optional[str] = None,
        ise_password: Optional[str] = None,
        # Notifications
        slack_webhook_url: Optional[str] = None,
        pagerduty_routing_key: Optional[str] = None,
        # Ticketing
        jira_url: Optional[str] = None,
        jira_user: Optional[str] = None,
        jira_token: Optional[str] = None,
        jira_project: Optional[str] = None,
        # AD (for credential revocation)
        ad_server: Optional[str] = None,
        ad_user: Optional[str] = None,
        ad_password: Optional[str] = None,
        ad_base_dn: Optional[str] = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.defender_url = defender_url
        self.defender_token = defender_token
        self.crowdstrike_url = crowdstrike_url
        self.crowdstrike_token = crowdstrike_token
        self.sentinelone_url = sentinelone_url
        self.sentinelone_token = sentinelone_token
        self.ise_url = ise_url
        self.ise_user = ise_user
        self.ise_password = ise_password
        self.slack_webhook_url = slack_webhook_url
        self.pagerduty_routing_key = pagerduty_routing_key
        self.jira_url = jira_url
        self.jira_user = jira_user
        self.jira_token = jira_token
        self.jira_project = jira_project
        self.ad_server = ad_server
        self.ad_user = ad_user
        self.ad_password = ad_password
        self.ad_base_dn = ad_base_dn

    # ------------------------------------------------------------------

    async def execute(self, action: str, alert: Alert, params: Dict[str, Any]) -> str:
        handlers = {
            "quarantine_host": self._quarantine,
            "snapshot_honeypot": self._snapshot,
            "extract_iocs": self._extract_iocs,
            "defender_isolate": self._defender_isolate,
            "crowdstrike_isolate": self._crowdstrike_isolate,
            "sentinelone_isolate": self._sentinelone_isolate,
            "ise_quarantine": self._ise_quarantine,
            "notify_slack": self._notify_slack,
            "page_oncall": self._page_oncall,
            "create_jira_ticket": self._create_jira_ticket,
            "disable_ad_account": self._disable_ad_account,
            "block_ip_firewall": self._block_ip_firewall,
        }
        handler = handlers.get(action)
        if handler is None:
            logger.warning("Unknown SOAR action: %s", action)
            return f"unknown-action:{action}"
        try:
            return await handler(alert, params)
        except Exception as exc:
            logger.error("SOAR action %s failed: %s", action, exc)
            return f"error:{action}:{exc}"

    # ------------------------------------------------------------------
    # Evidence / forensics
    # ------------------------------------------------------------------

    async def _quarantine(self, alert: Alert, params: Dict) -> str:
        self._append_log("quarantine.log", {
            "ts": _now(), "action": "quarantine", "ip": alert.source_ip,
            "rule": alert.rule_name, "session": alert.session_id,
        })
        return "quarantine-queued"

    async def _snapshot(self, alert: Alert, params: Dict) -> str:
        entry = {
            "ts": _now(), "session_id": alert.session_id, "source_ip": alert.source_ip,
            "rule": alert.rule_name, "metadata": alert.metadata,
            "checksum": hashlib.sha256(json.dumps(alert.metadata, default=str).encode()).hexdigest(),
        }
        self._append_log("snapshots.log", entry)
        return "snapshot-queued"

    async def _extract_iocs(self, alert: Alert, params: Dict) -> str:
        iocs = {
            "ts": _now(),
            "ips": [alert.source_ip] if alert.source_ip else [],
            "domains": list(alert.metadata.get("domains", [])),
            "hashes": list(alert.metadata.get("hashes", [])),
            "rule": alert.rule_name,
        }
        self._append_log("iocs.log", iocs)
        return "iocs-extracted"

    # ------------------------------------------------------------------
    # EDR isolation
    # ------------------------------------------------------------------

    async def _defender_isolate(self, alert: Alert, params: Dict) -> str:
        if not (self.defender_url and self.defender_token and alert.source_ip):
            return "defender-missing-config"
        defender_isolate(self.defender_url, self.defender_token, alert.source_ip)
        self._append_log("edr_actions.log", {"ts": _now(), "edr": "defender", "action": "isolate", "ip": alert.source_ip})
        return "defender-isolation-requested"

    async def _crowdstrike_isolate(self, alert: Alert, params: Dict) -> str:
        if not (self.crowdstrike_url and self.crowdstrike_token and alert.source_ip):
            return "crowdstrike-missing-config"
        cs_isolate(self.crowdstrike_url, self.crowdstrike_token, alert.source_ip)
        self._append_log("edr_actions.log", {"ts": _now(), "edr": "crowdstrike", "action": "isolate", "ip": alert.source_ip})
        return "crowdstrike-isolation-requested"

    async def _sentinelone_isolate(self, alert: Alert, params: Dict) -> str:
        from .drivers.sentinelone import isolate_device as s1_isolate
        if not (self.sentinelone_url and self.sentinelone_token and alert.source_ip):
            return "sentinelone-missing-config"
        s1_isolate(self.sentinelone_url, self.sentinelone_token, alert.source_ip)
        self._append_log("edr_actions.log", {"ts": _now(), "edr": "sentinelone", "action": "isolate", "ip": alert.source_ip})
        return "sentinelone-isolation-requested"

    async def _ise_quarantine(self, alert: Alert, params: Dict) -> str:
        if not (self.ise_url and self.ise_user and self.ise_password and alert.source_ip):
            return "ise-missing-config"
        quarantine_mac(self.ise_url, self.ise_user, self.ise_password, alert.source_ip)
        return "ise-quarantine-requested"

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    async def _notify_slack(self, alert: Alert, params: Dict) -> str:
        if not self.slack_webhook_url:
            return "slack-not-configured"
        channel = params.get("channel", "#soc-alerts")
        message = {
            "channel": channel,
            "text": (
                f":rotating_light: *ADG Alert: {alert.rule_name}*\n"
                f"Source IP: `{alert.source_ip}`  |  Session: `{alert.session_id}`\n"
                f"Timestamp: {_now()}"
            ),
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(self.slack_webhook_url, json=message)
            resp.raise_for_status()
        return "slack-notified"

    async def _page_oncall(self, alert: Alert, params: Dict) -> str:
        if not self.pagerduty_routing_key:
            return "pagerduty-not-configured"
        severity = params.get("severity", "critical")
        payload = {
            "routing_key": self.pagerduty_routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"ADG Alert: {alert.rule_name} — {alert.source_ip}",
                "severity": severity,
                "source": "adg-soar",
                "timestamp": _now(),
                "custom_details": alert.metadata,
            },
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue", json=payload
            )
            resp.raise_for_status()
        return "pagerduty-triggered"

    # ------------------------------------------------------------------
    # Ticketing
    # ------------------------------------------------------------------

    async def _create_jira_ticket(self, alert: Alert, params: Dict) -> str:
        if not (self.jira_url and self.jira_user and self.jira_token and self.jira_project):
            return "jira-not-configured"
        priority = params.get("priority", "High")
        issue = {
            "fields": {
                "project": {"key": self.jira_project},
                "summary": f"[ADG] {alert.rule_name} — {alert.source_ip}",
                "description": (
                    f"*Rule:* {alert.rule_name}\n"
                    f"*Source IP:* {alert.source_ip}\n"
                    f"*Session:* {alert.session_id}\n"
                    f"*Timestamp:* {_now()}\n\n"
                    f"*Metadata:*\n{{noformat}}{json.dumps(alert.metadata, indent=2, default=str)}{{noformat}}"
                ),
                "issuetype": {"name": "Incident"},
                "priority": {"name": priority},
            }
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{self.jira_url.rstrip('/')}/rest/api/2/issue",
                json=issue,
                auth=(self.jira_user, self.jira_token),
            )
            resp.raise_for_status()
            key = resp.json().get("key", "unknown")
        return f"jira-created:{key}"

    # ------------------------------------------------------------------
    # Identity response
    # ------------------------------------------------------------------

    async def _disable_ad_account(self, alert: Alert, params: Dict) -> str:
        account_name = params.get("account_name") or alert.metadata.get("username")
        if not (self.ad_server and account_name):
            return "ad-missing-config"
        from ldap3 import ALL, MODIFY_REPLACE, Connection, Server
        server = Server(self.ad_server, get_info=ALL)
        with Connection(server, user=self.ad_user, password=self.ad_password, auto_bind=True) as conn:
            dn = f"CN={account_name},{self.ad_base_dn}"
            conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [514])]})
        self._append_log("ad_actions.log", {"ts": _now(), "action": "disable", "account": account_name})
        return f"ad-disabled:{account_name}"

    # ------------------------------------------------------------------
    # Network controls
    # ------------------------------------------------------------------

    async def _block_ip_firewall(self, alert: Alert, params: Dict) -> str:
        """
        Generic IP block — appends to a block list file that can be consumed
        by a firewall automation layer (e.g. a script that feeds iptables / pfSense).
        For WAF integration pass waf_webhook_url in params.
        """
        ip = alert.source_ip or params.get("ip")
        if not ip:
            return "block-ip-missing-ip"
        self._append_log("blocked_ips.log", {
            "ts": _now(), "ip": ip, "rule": alert.rule_name,
            "reason": params.get("reason", "honeypot-engagement"),
        })
        waf_url = params.get("waf_webhook_url")
        if waf_url:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(waf_url, json={"block_ip": ip})
        return f"ip-blocked:{ip}"

    # ------------------------------------------------------------------

    def _append_log(self, filename: str, entry: Dict[str, Any]) -> None:
        path = self.output_dir / filename
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
