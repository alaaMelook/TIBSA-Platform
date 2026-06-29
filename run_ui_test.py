import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        console_logs = []
        page.on('console', lambda msg: console_logs.append(msg.text) if 'INVESTIGATION' in msg.text else None)
        
        await page.goto('http://localhost:3000/login')
        await page.fill('input[type="email"]', 'admin@tibsa.com')
        await page.fill('input[type="password"]', 'password')
        await page.click('button[type="submit"]')
        await page.wait_for_timeout(3000)
        await page.goto('http://localhost:3000/dashboard/investigations')
        
        # Fill Target
        await page.fill('input[placeholder*="https://"]', 'http://localhost:8083/sqli_1.php')
        
        # Wait for the checkboxes to be visible
        await page.wait_for_selector('text=Security Headers', timeout=10000)
        
        # Uncheck all checked checkboxes except SQLi
        checkboxes = await page.query_selector_all('input[type="checkbox"]')
        for cb in checkboxes:
            is_checked = await cb.is_checked()
            parent = await cb.evaluate_handle('el => el.parentElement.innerText')
            text = str(await parent.json_value()).lower()
            if 'sql' not in text and is_checked:
                await cb.click()
            elif 'sql injection' in text and not is_checked:
                await cb.click()

        # Auth toggle
        auth_toggle_parent = await page.query_selector('text=Automated Login')
        if auth_toggle_parent:
             parent = await auth_toggle_parent.evaluate_handle('el => el.closest("div.flex.items-center.justify-between.cursor-pointer")')
             await parent.click()
             
             await page.fill('input[placeholder*="login.php"]', 'http://localhost:8083/login.php')
             await page.fill('input[placeholder*="username"]', 'bee')
             await page.fill('input[type="password"]', 'bug')
             await page.select_option('select', 'low')

        # Submit
        await page.click('button:has-text("Launch Investigation")')
        await page.wait_for_timeout(3000)
        
        print("--- FRONTEND LOGS ---")
        for log in console_logs:
            print(log)
            
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
