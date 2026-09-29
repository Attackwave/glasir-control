// Drives the console's single sign-on in Chromium. Usage:
//   node sso-browser.js <base-url> <expect: signed-in|refused> [screenshot]
const { chromium } = require('playwright');
(async () => {
  const [base, expect, shot] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  page.on('console', m => m.type() === 'error' && errors.push(m.text()));
  await page.goto(`${base}/review`);
  await page.click('#sso-button');
  await page.waitForSelector('#app:not([hidden]), #signin-error:not([hidden])', { timeout: 15000 });
  if (shot) await page.screenshot({ path: shot });
  const signedIn = await page.isVisible('#app');
  const detail = signedIn ? await page.textContent('#user') : await page.textContent('#signin-error');
  const clean = !new URL(page.url()).search;
  await browser.close();
  const got = signedIn ? 'signed-in' : 'refused';
  console.log(`  ${got === expect && clean && !errors.length ? 'ok  ' : 'FAIL'}  ${expect}: ${detail}`);
  if (errors.length) console.log(`        page errors: ${errors.join(' | ')}`);
  if (!clean) console.log('        the sign-on code stayed in the address bar');
  process.exit(got === expect && clean && !errors.length ? 0 : 1);
})();
