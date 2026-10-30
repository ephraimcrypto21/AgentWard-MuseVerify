"""Browser acceptance against the explicit offline dashboard, never production controls."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright


def main(base='http://127.0.0.1:18081'):
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1000})
        errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(base,wait_until='networkidle')
        assert page.locator('[id^="card-"]').count()==7
        assert page.locator('#ensembleMode option').count()==5
        page.locator('#ensembleMode').select_option('meta_only')
        page.locator('#retestProviders').click()
        page.wait_for_function('!document.getElementById("retestProviders").disabled')
        page.locator('#steeringInput').fill('Forbid credential logging')
        page.get_by_role('button',name='Add restriction').click()
        page.wait_for_function('document.getElementById("steeringStatus").textContent.includes("Policy revision")')
        page.get_by_role('tab',name='Cross-File Taint Map',exact=True).click()
        assert page.locator('#taintPanel').is_visible()
        page.get_by_role('tab',name='📊 Executive Security Brief & Cross-File Taint Map').click()
        assert page.locator('#briefPanel').is_visible()
        # Exercise both renderers using a captured simulation diff from the E2E run.
        events=json.loads(Path('reports/dry_run_e2e_telemetry.json').read_text())
        diff=next(json.loads(m['data']) for m in events if m['type']=='patch_diff')
        page.evaluate('(diff)=>{currentDiff=diff;renderDiff()}',diff)
        assert 'SIMULATED' in page.locator('#diffFile').inner_text()
        page.locator('#diffMode').select_option('split')
        assert page.locator('#diffSplit').is_visible()
        page.locator('#diffMode').select_option('unified')
        assert page.locator('#diffUnified').is_visible()
        page.screenshot(path='reports/dashboard-browser-smoke.png',full_page=True)
        page.set_viewport_size({'width':390,'height':844})
        assert page.locator('#steeringInput').is_visible()
        page.screenshot(path='reports/dashboard-mobile.png',full_page=True)
        assert not errors,errors
        browser.close()
    result={'page_errors':errors,'phase_cards':7,'ensemble_modes':5,'steering':'passed','executive_tabs':'passed','diff_modes':'passed'}
    Path('reports/browser_verification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__': main()
