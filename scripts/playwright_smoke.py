import asyncio
from playwright.async_api import async_playwright

async def run():
    url = 'http://localhost:5000/stats'
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        logs = []
        page.on('console', lambda msg: logs.append(f'console:{msg.type}:{msg.text}'))

        # Abort API endpoints to simulate offline/failure
        await page.route('**/api/stats', lambda route: route.abort())
        await page.route('**/api/system_health', lambda route: route.abort())

        print('Navigating to', url)
        resp = await page.goto(url, wait_until='domcontentloaded', timeout=15000)
        print('HTTP status:', resp.status if resp else 'no-response')

        # wait for our main element
        try:
            await page.wait_for_selector('#total-domains', timeout=5000)
        except Exception as e:
            print('total-domains not found:', e)

        # Give fetchStats a moment to try the APIs and fallback
        await asyncio.sleep(2)

        # Read fallback snapshot presence
        last = await page.evaluate('window._lastStats || null')
        print('window._lastStats present:', bool(last))

        # Try to click first tech row if available
        try:
            row = await page.query_selector('#top-tech-body tr')
            if row:
                await row.click()
                # wait for modal
                await page.wait_for_selector('#techModal', timeout=3000)
                visible = await page.evaluate("document.getElementById('techModal').style.display !== 'none'")
                print('modal visible:', visible)
                title = await page.evaluate("document.getElementById('modal-title')?.textContent || ''")
                print('modal title:', title)
        except Exception as e:
            print('modal interaction failed:', e)

        # print some console logs captured
        print('--- console logs ---')
        for l in logs[-30:]:
            print(l)

        await browser.close()

if __name__ == '__main__':
    asyncio.run(run())
