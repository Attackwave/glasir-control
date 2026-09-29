// Signs in to the console through a real Keycloak login page. Usage:
//   node sso-keycloak-browser.js <console-url> <user> <password> [screenshot]
const { chromium } = require('playwright');
(async () => {
  const [base, user, password, shot] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  page.on('console', m => m.type() === 'error' && errors.push(m.text()));
  await page.goto(`${base}/review`);
  await page.click('#sso-button');
  await page.waitForSelector('#username', { timeout: 30000 });
  await page.fill('#username', user);
  await page.fill('#password', password);
  await page.click('#kc-login');
  await page.waitForSelector('#app:not([hidden]), #signin-error:not([hidden])', { timeout: 30000 });
  if (shot) await page.screenshot({ path: shot });
  const signedIn = await page.isVisible('#app');
  const who = signedIn ? `${await page.textContent('#user')} (${await page.textContent('#role')})` : await page.textContent('#signin-error');
  await browser.close();
  const ok = signedIn && !errors.length;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  signed in through Keycloak: ${who}`);
  if (errors.length) console.log(`        page errors: ${errors.join(' | ')}`);
  process.exit(ok ? 0 : 1);
})();
