from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

import requests

from browser_probe_runner import collect_browser_observations


# =========================
# Data models
# =========================

@dataclass
class NetworkSnapshot:
    dns_resolvers: List[str]
    public_ip: Optional[str]


@dataclass
class BrowserObservations:
    timezone: str
    language: str
    languages: List[str]
    webrtc_summary: str


@dataclass
class RiskFinding:
    score: int
    explanation: str


@dataclass
class RiskReport:
    generated_at: datetime
    network: NetworkSnapshot
    browser: BrowserObservations
    findings: List[RiskFinding]
    total_score: int


# =========================
# Network inspection
# =========================

def run_shell_quietly(command: str) -> str:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=True,
    )
    return completed.stdout


_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def read_dns_resolvers_from_ipconfig() -> List[str]:
    raw = run_shell_quietly("ipconfig /all")

    found: List[str] = []

    for line in raw.splitlines():
        if "DNS" not in line.upper():
            continue

        for ip in _IPV4_PATTERN.findall(line):
            if ip not in found:
                found.append(ip)

    return found


def ask_the_internet_for_my_ip(timeout_seconds: float = 4.0) -> Optional[str]:
    try:
        response = requests.get(
            "https://api.ipify.org",
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        return response.text.strip()
    except Exception:
        return None


def take_network_snapshot() -> NetworkSnapshot:
    return NetworkSnapshot(
        dns_resolvers=read_dns_resolvers_from_ipconfig(),
        public_ip=ask_the_internet_for_my_ip(),
    )


# =========================
# Risk assessment
# =========================

def assess_dns_risk(dns_servers: List[str]) -> List[RiskFinding]:
    findings: List[RiskFinding] = []

    for server in dns_servers:
        if server.startswith(("8.8.8.", "8.8.4.")):
            findings.append(RiskFinding(
                score=20,
                explanation=(
                    "DNS-запросы обслуживаются Google Public DNS. "
                    "Доменные имена видны третьей стороне, не связанной с VPN."
                ),
            ))
        elif server.startswith("1.1.1."):
            findings.append(RiskFinding(
                score=15,
                explanation=(
                    "DNS-запросы обслуживаются Cloudflare DNS. "
                    "Это отдельный наблюдатель, независимый от VPN."
                ),
            ))
        elif server.startswith(("10.", "192.168.")):
            findings.append(RiskFinding(
                score=0,
                explanation=(
                    "DNS-сервер находится в частном диапазоне. "
                    "Вероятно, используется VPN или локальный резолвер."
                ),
            ))
        else:
            findings.append(RiskFinding(
                score=10,
                explanation=(
                    f"Используется нестандартный DNS-сервер ({server}). "
                    "Наблюдатель неизвестен."
                ),
            ))

    return findings


def assess_browser_risks(browser: BrowserObservations) -> List[RiskFinding]:
    findings: List[RiskFinding] = []

    if browser.timezone and not browser.timezone.startswith("Europe/"):
        findings.append(RiskFinding(
            score=10,
            explanation=(
                "Timezone отличается от типичных локаций VPN-серверов. "
                "Может использоваться для корреляции с IP."
            ),
        ))

    if browser.language.startswith("ru"):
        findings.append(RiskFinding(
            score=5,
            explanation=(
                "Языковые настройки стабильны и региональны. "
                "Сами по себе безопасны, но усиливают другие сигналы."
            ),
        ))

    if "local ip" in browser.webrtc_summary.lower():
        findings.append(RiskFinding(
            score=30,
            explanation=(
                "WebRTC раскрывает локальный IP-адрес. "
                "Это сильный deanonymization-вектор."
            ),
        ))

    return findings


def build_risk_report(
    network: NetworkSnapshot,
    browser: BrowserObservations,
) -> RiskReport:
    findings: List[RiskFinding] = []

    findings.extend(assess_dns_risk(network.dns_resolvers))
    findings.extend(assess_browser_risks(browser))

    total_score = sum(f.score for f in findings)

    return RiskReport(
        generated_at=datetime.utcnow(),
        network=network,
        browser=browser,
        findings=findings,
        total_score=total_score,
    )


# =========================
# Output
# =========================

def print_risk_report(report: RiskReport) -> None:
    print("\n=== Privacy Risk Report ===\n")
    print(f"Generated at (UTC): {report.generated_at.isoformat()}\n")

    print("Network:")
    print(f"  DNS: {', '.join(report.network.dns_resolvers) or 'unknown'}")
    print(f"  Public IP: {report.network.public_ip or 'unknown'}\n")

    print("Browser:")
    print(f"  Timezone: {report.browser.timezone}")
    print(f"  Language: {report.browser.language}")
    print(f"  Languages: {', '.join(report.browser.languages)}")
    print(f"  WebRTC: {report.browser.webrtc_summary}\n")

    print("Findings:")
    for f in report.findings:
        print(f"  +{f.score:02d} — {f.explanation}")

    print(f"\nTotal risk score: {report.total_score} / 100\n")


# =========================
# Entry point
# =========================

def main() -> None:
    network = take_network_snapshot()

    raw_browser = collect_browser_observations()
    browser = BrowserObservations(
        timezone=raw_browser["timezone"],
        language=raw_browser["language"],
        languages=raw_browser["languages"],
        webrtc_summary=raw_browser["webrtc_summary"],
    )

    report = build_risk_report(network, browser)
    print_risk_report(report)


if __name__ == "__main__":
    main()
