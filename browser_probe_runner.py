from __future__ import annotations

from pathlib import Path
from playwright.sync_api import sync_playwright


def collect_browser_observations() -> dict:
    """
    Открывает локальную fingerprint_check.html
    и возвращает browser-наблюдения как словарь.
    """

    probe_file = Path(__file__).parent / "browser_probe" / "fingerprint_check.html"
    probe_url = probe_file.as_uri()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto(probe_url)

        # Ждём, пока страница прогрузит JS
        page.wait_for_timeout(500)

        timezone = page.evaluate(
            "Intl.DateTimeFormat().resolvedOptions().timeZone"
        )

        language = page.evaluate("navigator.language")
        languages = page.evaluate("navigator.languages")

        webrtc_summary = page.evaluate(
            """
            () => {
                if (!window.__webrtcResult) {
                    return "no data";
                }
                return window.__webrtcResult;
            }
            """
        )

        browser.close()

    return {
        "timezone": timezone,
        "language": language,
        "languages": languages,
        "webrtc_summary": webrtc_summary,
    }
