from __future__ import annotations

import ipaddress
from typing import List

import yaml


def load_policy(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except FileNotFoundError:
        return {}


def is_allowed(subnet: str, allowed: List[str], blocked: List[str]) -> bool:
    net = ipaddress.ip_network(subnet)
    for blocked_net in blocked:
        candidate = ipaddress.ip_network(blocked_net)
        if isinstance(net, ipaddress.IPv4Network) and isinstance(candidate, ipaddress.IPv4Network):
            if net.subnet_of(candidate):
                return False
        if isinstance(net, ipaddress.IPv6Network) and isinstance(candidate, ipaddress.IPv6Network):
            if net.subnet_of(candidate):
                return False
    if not allowed:
        return True
    for item in allowed:
        candidate = ipaddress.ip_network(item)
        if isinstance(net, ipaddress.IPv4Network) and isinstance(candidate, ipaddress.IPv4Network):
            if net.subnet_of(candidate):
                return True
        if isinstance(net, ipaddress.IPv6Network) and isinstance(candidate, ipaddress.IPv6Network):
            if net.subnet_of(candidate):
                return True
    return False

