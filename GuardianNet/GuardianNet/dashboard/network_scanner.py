"""Backward-compatible entry point for the safe real network scanner."""

from .services.network_scanner import scan_network


def scan_local_network():
    return scan_network()
