from __future__ import annotations

import logging
from typing import Dict, List

from ldap3 import ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Connection, Server

logger = logging.getLogger("adg.ad")


def _connect(server_uri: str, user: str, password: str) -> tuple[Server, Connection]:
    server = Server(server_uri, get_info=ALL)
    conn = Connection(server, user=user, password=password, auto_bind=True)
    return server, conn


def _user_dn(account_name: str, base_dn: str, ou: str = "") -> str:
    container = ou if ou else base_dn
    return f"CN={account_name},{container}"


def create_decoy_user(
    server_uri: str,
    user: str,
    password: str,
    base_dn: str,
    account_name: str,
    attributes: Dict[str, str],
    ou: str = "",
) -> None:
    _, conn = _connect(server_uri, user, password)
    dn = _user_dn(account_name, base_dn, ou)
    with conn:
        conn.add(dn, ["user"], attributes)
        if not conn.result["result"] == 0:
            logger.warning("AD create_decoy_user result: %s", conn.result)


def disable_user(
    server_uri: str, user: str, password: str, base_dn: str, account_name: str,
    ou: str = "",
) -> None:
    _, conn = _connect(server_uri, user, password)
    dn = _user_dn(account_name, base_dn, ou)
    with conn:
        # 514 = ACCOUNTDISABLE (0x0002)
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [514])]})


def enable_user(
    server_uri: str, user: str, password: str, base_dn: str, account_name: str,
    ou: str = "",
) -> None:
    _, conn = _connect(server_uri, user, password)
    dn = _user_dn(account_name, base_dn, ou)
    with conn:
        # 512 = NORMAL_ACCOUNT (0x0200)
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})


def manage_group_membership(
    server_uri: str,
    user: str,
    password: str,
    base_dn: str,
    account_name: str,
    group_dn: str,
    add: bool = True,
    ou: str = "",
) -> None:
    """Add or remove a decoy user from an AD security group."""
    _, conn = _connect(server_uri, user, password)
    user_dn = _user_dn(account_name, base_dn, ou)
    op = MODIFY_ADD if add else MODIFY_DELETE
    with conn:
        conn.modify(group_dn, {"member": [(op, [user_dn])]})
        if not conn.result["result"] == 0:
            logger.warning("AD group modify result: %s", conn.result)


def list_decoy_users(
    server_uri: str, user: str, password: str, base_dn: str
) -> List[Dict[str, str]]:
    """Return all AD users whose description contains 'ADG-DECOY'."""
    _, conn = _connect(server_uri, user, password)
    with conn:
        conn.search(
            base_dn,
            "(description=*ADG-DECOY*)",
            attributes=["cn", "sAMAccountName", "userAccountControl", "description"],
        )
        results = []
        for entry in conn.entries:
            results.append({
                "dn": str(entry.entry_dn),
                "cn": str(entry.cn),
                "sAMAccountName": str(entry.sAMAccountName),
                "userAccountControl": str(entry.userAccountControl),
            })
        return results
