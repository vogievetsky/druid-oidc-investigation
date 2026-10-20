// Real-browser (Chromium via Playwright) check of the web console around OIDC session expiry.
//
// usage: node browser_expiry.js [outDir] [waitSeconds]
//   outDir       where screenshots go (default: ../evidence)
//   waitSeconds  how long to idle so the IdP token expires (default: 150; realm token lifespan is 120s)
//
// Env: DRUID_URL (default http://localhost:8888), OIDC_USER / OIDC_PASSWORD (default alice / alice)
const path = require('path');
const { chromium } = require('playwright-chromium');

const outDir = process.argv[2] || path.join(__dirname, '..', 'evidence');
const waitSeconds = Number(process.argv[3] || 150);
const DRUID_URL = process.env.DRUID_URL || 'http://localhost:8888';
const USER = process.env.OIDC_USER || 'alice';
const PASSWORD = process.env.OIDC_PASSWORD || 'alice';

const t0 = Date.now();
const log = (...a) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s]`, ...a);

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  page.on('console', m => m.type() === 'error' && log('  browser console error:', m.text().slice(0, 200)));
  page.on('requestfailed', r =>
    log('  request failed:', r.method(), r.url().slice(0, 100), r.failure()?.errorText),
  );

  log('open console');
  await page.goto(`${DRUID_URL}/unified-console.html`);
  log('landed on', page.url().slice(0, 80));
  await page.fill('#username', USER);
  await page.fill('#password', PASSWORD);
  await Promise.all([page.waitForURL(/\/unified-console\.html/), page.click('#kc-login')]);
  log('back on', page.url());
  await page.waitForTimeout(4000);
  const cookies = await page.context().cookies(DRUID_URL);
  log('router cookies stored by Chromium:', cookies.map(c => c.name).join(', '));
  await page.screenshot({ path: `${outDir}/1-logged-in.png` });

  const probe = async label => {
    const r = await page.evaluate(async () => {
      const out = {};
      try {
        const resp = await fetch('/druid/coordinator/v1/leader');
        out.fetch = `${resp.status} redirected=${resp.redirected}`;
      } catch (e) {
        out.fetch = `THREW ${e}`;
      }
      const xhr = headers =>
        new Promise(res => {
          const x = new XMLHttpRequest();
          x.open('GET', '/druid/coordinator/v1/leader');
          for (const [k, v] of Object.entries(headers)) x.setRequestHeader(k, v);
          x.onload = () =>
            res(
              `status ${x.status} www-authenticate=${x.getResponseHeader('WWW-Authenticate')} body=${String(
                x.responseText,
              ).slice(0, 40)}`,
            );
          x.onerror = () => res(`onerror (status ${x.status}) -> axios would report "Network Error"`);
          x.send();
        });
      out.xhr = await xhr({});
      out.xhrAjax = await xhr({ 'X-Requested-With': 'XMLHttpRequest' });
      return out;
    });
    log(`${label}: fetch                         -> ${r.fetch}`);
    log(`${label}: XHR (what the console does)   -> ${r.xhr}`);
    log(`${label}: XHR + X-Requested-With header -> ${r.xhrAjax}`);
  };

  await probe('fresh session');

  log(`waiting ${waitSeconds}s for the IdP token to expire...`);
  await page.waitForTimeout(waitSeconds * 1000);

  await probe('after expiry');

  log('click the "Services" tab in the console');
  await page.click('a[href="#services"]').catch(e => log('  could not click services:', e.message));
  await page.waitForTimeout(5000);
  await page.screenshot({ path: `${outDir}/2-after-expiry-services.png` });

  log('full page reload');
  await page.reload();
  await page.waitForLoadState('networkidle').catch(() => {});
  log('after reload, url =', page.url().slice(0, 90));
  log('login form shown?', (await page.locator('#username').count()) > 0);
  await page.waitForTimeout(3000);
  await page.screenshot({ path: `${outDir}/3-after-reload.png` });
  await probe('after reload');

  await browser.close();
})().catch(e => {
  console.error(e);
  process.exit(1);
});
