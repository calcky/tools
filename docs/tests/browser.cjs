// Set NODE_PATH (or PLAYWRIGHT_MODULE) to Playwright; the preview must be running.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const base = (process.argv[2] || 'http://127.0.0.1:8012').replace(/\/$/, '');
const screenshots = fs.mkdtempSync(path.join(os.tmpdir(), 'tools-docs-screenshots-'));
const references = ['cli', 'interfaces', 'routing', 'monitor-metrics', 'packet-path'].map(name => `netlens/docs/${name}/`);
const routes = ['', 'getting-started/', 'irqtop/', 'netping/', 'flowgen/', 'cttop/', 'netlens/', 'bpftrace/', 'nettrace/', 'netcap/', ...references];

(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.CHROMIUM_PATH ? {executablePath: process.env.CHROMIUM_PATH} : {}),
  });
  const errors = [];
  try {
    for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
      const context = await browser.newContext({viewport});
      const page = await context.newPage();
      page.on('pageerror', error => errors.push(error.message));
      for (const locale of ['zh', 'en']) {
        const prefix = locale === 'en' ? 'en/' : '';
        for (const route of routes) {
          const response = await page.goto(`${base}/${prefix}${route}`);
          assert.equal(response.status(), 200);
          assert.equal(await page.locator('html').getAttribute('lang'), locale);
          assert.ok(await page.locator('article h1').isVisible());
          for (const img of await page.locator('article img').all()) {
            await img.scrollIntoViewIfNeeded();
            assert.ok(await img.evaluate(node => node.complete && node.naturalWidth >= 1200), `${locale}/${route} has a missing screenshot`);
            assert.ok(await img.getAttribute('alt'));
            assert.ok(await img.evaluate(node => {
              const rect = node.getBoundingClientRect();
              const article = node.closest('article').getBoundingClientRect();
              return rect.left >= article.left - 1 && rect.right <= article.right + 1;
            }), `${locale}/${route} screenshot overflows`);
            const fullSize = await img.evaluate(node => node.closest('a')?.href);
            assert.equal(fullSize, await img.evaluate(node => node.src));
          }
          const article = await page.locator('article').innerText();
          assert.ok(!/\buping\b|原名|previously named/i.test(article));
          if (locale === 'en') assert.ok(!/[\u4e00-\u9fff]/.test(article));
          assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${locale}/${route} overflows at ${viewport.width}px`);
          if (['netping/', 'flowgen/', 'nettrace/', 'netcap/'].includes(route)) {
            assert.ok(await page.locator('pre code').count() > 0);
            assert.ok(await page.locator('a[href$="-release"]').count() > 0);
          }
        }
      }

      // Switch homepages and tool pages in both directions through the real menu.
      for (const route of ['', 'flowgen/', 'netping/', 'netlens/', 'nettrace/', 'netcap/', ...references]) {
        await page.goto(`${base}/${route}`);
        await page.locator('.md-select > button').click();
        await page.locator('.md-select a[hreflang="en"]').click();
        assert.equal(new URL(page.url()).pathname, `/en/${route}`);
        await page.locator('.md-select > button').click();
        await page.locator('.md-select a[hreflang="zh"]').click();
        assert.equal(new URL(page.url()).pathname, `/${route}`);
      }

      // Follow the expanded netlens submenu, including inside the mobile drawer.
      for (const locale of ['zh', 'en']) {
        const prefix = locale === 'en' ? 'en/' : '';
        await page.goto(`${base}/${prefix}netlens/`);
        if (viewport.width < 600) {
          await page.locator('label[for="__drawer"].md-header__button').click();
        }
        await page.locator('.md-sidebar--primary a[href="docs/monitor-metrics/"]').click();
        assert.equal(new URL(page.url()).pathname, `/${prefix}netlens/docs/monitor-metrics/`);
        const heading = await page.locator('article h1').evaluate(element => {
          const copy = element.cloneNode(true);
          copy.querySelector('.headerlink')?.remove();
          return copy.textContent.trim();
        });
        assert.equal(heading, locale === 'en' ? 'Metrics And Data Status' : '指标与数据状态');
      }

      await page.goto(`${base}/en/netping/`);
      await page.locator('label[for="__palette_1"]').click();
      assert.equal(await page.locator('body').getAttribute('data-md-color-scheme'), 'slate');
      await page.locator('label[for="__palette_0"]').click();
      assert.equal(await page.locator('body').getAttribute('data-md-color-scheme'), 'default');

      if (viewport.width < 600) {
        await page.locator('label[for="__drawer"].md-header__button').click();
        await page.locator('.md-sidebar--primary a[href="../cttop/"]').click();
        assert.equal(new URL(page.url()).pathname, '/en/cttop/');
      }

      // Search must return a real result in each language, not only load its index.
      for (const locale of ['zh', 'en']) {
        await page.goto(`${base}/${locale === 'en' ? 'en/' : ''}`);
        if (viewport.width < 600) {
          await page.locator('label[for="__search"].md-header__button').click();
        }
        const input = page.locator('input[data-md-component="search-query"]');
        await input.fill(locale === 'zh' ? '中断' : 'interrupt');
        await page.waitForFunction(() => [...document.querySelectorAll('.md-search-result__link')]
          .some(link => link.textContent.includes('irqtop')));
        assert.match(await page.locator('.md-search-result').innerText(), /irqtop/);
      }

      // Deep links must reach the XDP explanation rather than the top of the page.
      for (const locale of ['zh', 'en']) {
        const prefix = locale === 'en' ? 'en/' : '';
        await page.goto(`${base}/${prefix}netlens/docs/packet-path/#xdp`);
        assert.ok(await page.locator('h2#xdp').isVisible());
        assert.ok(await page.locator('article').innerText().then(text => text.includes('XDP_REDIRECT')));
        await page.screenshot({path: path.join(screenshots, `netlens-xdp-${locale}-${viewport.width}.png`)});
      }

      for (const [name, route] of [['overview', ''], ['netping-en', 'en/netping/'], ['flowgen', 'flowgen/'], ['netlens', 'netlens/'], ['netlens-metrics', 'netlens/docs/monitor-metrics/'], ['netlens-paths', 'netlens/docs/packet-path/'], ['netlens-paths-en', 'en/netlens/docs/packet-path/']]) {
        await page.goto(`${base}/${route}`);
        await page.screenshot({path: path.join(screenshots, `${name}-${viewport.width}.png`), fullPage: true});
      }
      console.log(`PASS ${viewport.width}x${viewport.height}: ${routes.length * 2} pages, language menus, theme, navigation and bilingual search`);
      await context.close();
    }
    assert.deepEqual(errors, []);
    console.log(`Screenshots: ${screenshots}`);
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
