import asyncio
import logging
from pathlib import Path
from typing import Optional, Tuple
from playwright.async_api import async_playwright
import uuid

logger = logging.getLogger("aegis.dast_scanner")

class DASTScanner:
    """
    Dynamic Application Security Testing (DAST) Module.
    Uses Playwright headless browser to execute DOM XSS payloads and capture screenshots.
    """

    def __init__(self, timeout_seconds: int = 15):
        self.timeout = timeout_seconds * 1000  # ms

    async def verify_xss_poc(self, code_snippet: str, payload: str = "<img src=x onerror=window.STRIX_XSS=true>") -> Tuple[bool, Optional[str]]:
        """
        Takes a vulnerable code snippet (HTML/JS) and a payload, wraps it in a test page,
        runs it in a headless browser, and checks if the payload triggers.
        Returns: (True/False, Path to screenshot if triggered)
        """
        temp_id = str(uuid.uuid4())[:8]
        html_file = Path(f"/tmp/aegis_poc_{temp_id}.html")
        screenshot_file = Path(f"/tmp/aegis_screenshot_{temp_id}.png")

        # Create a test harness HTML
        test_html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Aegis PoC</title></head>
        <body>
            <div id="aegis-container"></div>
            <script>
                // Intercept alerts or custom flags
                window.STRIX_XSS = false;
                window.alert = function(msg) {{ window.STRIX_XSS = true; }};
                
                // Inject the vulnerable snippet
                try {{
                    const payload = `{payload}`;
                    const container = document.getElementById("aegis-container");
                    
                    {code_snippet}
                }} catch (e) {{
                    console.error("Aegis PoC Error:", e);
                }}
            </script>
        </body>
        </html>
        """
        html_file.write_text(test_html, encoding="utf-8")

        xss_triggered = False
        screenshot_path = None

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                page.on("console", lambda msg: logger.debug(f"PoC Console: {msg.text}"))
                page.on("dialog", lambda dialog: dialog.accept()) # Auto-accept alerts

                await page.goto(f"file://{html_file.absolute()}")
                await asyncio.sleep(1)
                
                is_xss = await page.evaluate("window.STRIX_XSS")
                
                if is_xss:
                    xss_triggered = True
                    await page.evaluate("""
                        const div = document.createElement('div');
                        div.style.position = 'fixed';
                        div.style.top = '0';
                        div.style.left = '0';
                        div.style.width = '100%';
                        div.style.background = 'red';
                        div.style.color = 'white';
                        div.style.fontSize = '24px';
                        div.style.fontWeight = 'bold';
                        div.style.textAlign = 'center';
                        div.style.padding = '10px';
                        div.style.zIndex = '9999';
                        div.innerText = '🔥 STRIX ENGINE XSS VERIFIED 🔥';
                        document.body.appendChild(div);
                    """)
                    await page.screenshot(path=str(screenshot_file))
                    screenshot_path = str(screenshot_file)

                await browser.close()
        except Exception as e:
            logger.error(f"DAST execution failed: {e}")
        finally:
            if html_file.exists():
                html_file.unlink()

        return xss_triggered, screenshot_path
