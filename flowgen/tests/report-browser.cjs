// NODE_PATH must include Playwright; pass one or more generated report.html paths.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {chromium} = require('playwright');
const {parse} = require('csv-parse/sync');

(async () => {
  assert.ok(process.argv.length > 2, 'Provide at least one events report.html');
  const browser = await chromium.launch({headless: true,
    ...(process.env.CHROMIUM_PATH ? {executablePath: process.env.CHROMIUM_PATH} : {})});
  try {
    const context = await browser.newContext({offline: true, viewport: {width: 1440, height: 1100}});
    const page = await context.newPage();
    const errors = [], external = [];
    page.on('pageerror', e => errors.push(e.message));
    page.on('request', r => {if (/^https?:/.test(r.url())) external.push(r.url());});
    async function download(selector) {
      const pending=page.waitForEvent('download');
      await page.locator(selector).click();
      const file=await pending;
      assert.equal(await file.failure(), null);
      return {name:file.suggestedFilename(),bytes:fs.readFileSync(await file.path())};
    }
    for (const file of process.argv.slice(2)) {
      await page.goto(pathToFileURL(path.resolve(file)).href);
      assert.equal(await page.locator('#render-error').textContent(), '');
      assert.equal(await page.locator('#status').textContent(), 'COMPLETE');
      assert.equal(await page.locator('.matrix > section').count(), 4);
      assert.equal(await page.locator('.prototype-switcher').count(), 0);
      assert.ok(await page.locator('#panel-latency').isVisible());
      const payload = await page.locator('#report-data').textContent();
      const data = JSON.parse(payload);
      const summary = data.tables.summary[0];
      assert.equal(await page.locator('#statistics-scope').textContent(), 'Full-run statistics');
      assert.match(await page.locator('#anomaly-summary').innerText(), /Recording\s+COMPLETE/);
      for(const [key,label] of [['failed','Failed sessions'],['timeout','Timeout records'],['limited','Local limited'],['skipped','Skipped requests'],['session_skipped','Skipped session slots']]) {
        if(BigInt(summary[key])>0n)assert.ok((await page.locator('#anomaly-summary').innerText()).includes(label));
      }
      if (Number(summary.response_timeout_pct) > 0 && Number(summary.response_timeout_pct) < 0.001) {
        assert.match(await page.locator('#metrics').innerText(), /<0\.001/);
      }
      const points = data.tables.timeline.filter(p => p.run === summary.run && p.protocol === summary.protocol);
      const attainment=(data.tables.attainment||[]).filter(row=>row.run===summary.run && row.protocol===summary.protocol);
      assert.equal(await page.locator('#attainment tbody tr').count(),3);
      assert.match(await page.locator('#attainment').innerText(),/Ready sessions \/ avg/);
      const readyRow=attainment.find(row=>row.metric==='ready');
      const sessionSeries=await page.evaluate(()=>echarts.getInstanceByDom(document.getElementById('sessions')).getOption().series);
      assert.ok(sessionSeries.some(series=>series.name==='Live'));
      if(readyRow?.actual==='NA') {
        assert.match(await page.locator('#attainment').innerText(),/Ready sampling unavailable/);
        assert.ok(!sessionSeries.some(series=>series.name==='Ready'));
      } else if(readyRow) {
        const readiness=data.tables.readiness.filter(row=>row.run===summary.run && row.protocol===summary.protocol);
        for(const [name,key] of [['Ready','ready_sessions'],['Deficit','deficit_sessions']]) {
          const series=sessionSeries.find(series=>series.name===name);
          assert.ok(series);
          assert.deepEqual(series.data.map(p=>p[1]),readiness.map(row=>row[key]==='NA'?null:Number(row[key])));
        }
      }
      const quality = await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('sample-quality')).getOption());
      const selected = await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('rtt')).getOption().legend[0].selected);
      for (const name of ['Avg', 'P90', 'P99']) assert.notEqual(selected[name], false);
      for (const name of ['P50', 'P95', 'Min', 'Max']) assert.equal(selected[name], false);
      assert.equal(quality.series[0].type, 'bar');
      assert.equal(quality.series[1].yAxisIndex, 1);
      assert.deepEqual(quality.series[0].data.map(p => p[1]), points.map(p => Number(p.rtt_samples)));
      assert.deepEqual(quality.series[1].data.map(p => p[1]), points.map(p => {
        const timeout = Math.round(Number(p.timeout_s) * Number(p.bucket_s));
        const resolved = timeout + Number(p.rtt_samples);
        return resolved > 0 ? 100 * timeout / resolved : null;
      }));
      assert.equal(await page.locator('canvas').count(), 5);
      assert.ok(await page.evaluate(() => [...document.querySelectorAll('canvas')].every(canvas => {
        const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
        let visible = 0;
        for (let i = 3; i < pixels.length; i += 4) if (pixels[i]) visible++;
        return visible > 1000;
      })), 'All four matrix charts and the shared navigator must render nonblank');
      const metrics=await page.locator('#metrics').innerText(),fullRange=await page.locator('#chart-range').innerText();
      const loadMetrics=await page.locator('#attainment').innerText();
      await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('rtt')).dispatchAction({type: 'dataZoom', start: 25, end: 75}));
      assert.equal(await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('sample-quality')).getOption().dataZoom[0].start), 25);
      assert.notEqual(await page.locator('#chart-range').innerText(),fullRange);
      assert.equal(await page.locator('#metrics').innerText(),metrics, 'Zoom never changes full-run summaries');
      assert.equal(await page.locator('#attainment').innerText(),loadMetrics,'Zoom never changes LOAD attainment');
      if(attainment.length){
        const exported=await download('#export-attainment');
        assert.equal(exported.name,`flowgen-${summary.protocol}-${summary.run}-attainment.csv`);
        assert.deepEqual(parse(exported.bytes,{columns:true}),attainment.map(row=>({...row,recording_status:'COMPLETE'})));
      }
      const summaryCsv=await download('#export-summary');
      assert.equal(summaryCsv.name,`flowgen-${summary.protocol}-${summary.run}-summary.csv`);
      assert.deepEqual(parse(summaryCsv.bytes,{columns:true}),[{...summary,recording_status:'COMPLETE',request_accounting_status:summary.response_timeout_status}]);
      const timelineCsv=await download('#export-timeline');
      assert.equal(timelineCsv.name,`flowgen-${summary.protocol}-${summary.run}-timeseries.csv`);
      assert.deepEqual(parse(timelineCsv.bytes,{columns:true}),points.map(point=>({...point,recording_status:'COMPLETE',request_accounting_status:summary.response_timeout_status})));
      await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('rtt')).dispatchAction({type:'legendToggleSelect',name:'P95'}));
      const png=await download('[data-chart-export="rtt"]');
      assert.equal(await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('rtt')).getOption().legend[0].selected.P95),true);
      assert.equal(await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('rtt')).getOption().dataZoom[0].start),25);
      await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('rtt')).dispatchAction({type:'legendToggleSelect',name:'P95'}));
      assert.match(png.name,new RegExp(`^flowgen-${summary.protocol}-${summary.run}-rtt-.*s\\.png$`));
      assert.deepEqual(png.bytes.subarray(0,8),Buffer.from([137,80,78,71,13,10,26,10]));
      assert.ok(png.bytes.readUInt32BE(16)>=1000);
      assert.ok(png.bytes.readUInt32BE(20)>570, 'PNG includes the title and range header');
      if(process.env.SCREENSHOT_DIR) {
        fs.mkdirSync(process.env.SCREENSHOT_DIR,{recursive:true});
        fs.writeFileSync(path.join(process.env.SCREENSHOT_DIR,summary.protocol+'-rtt-export.png'),png.bytes);
      }
      await page.locator('#reset').click();
      assert.equal(await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('sample-quality')).getOption().dataZoom[0].start), 0);
      assert.equal(await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('range')).getOption().dataZoom[0].start), 0);
      assert.equal(await page.locator('#chart-range').innerText(),fullRange);
      const traffic = await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('traffic')).getOption().series.map(s => s.name));
      assert.deepEqual(traffic, ['Sent', 'On-time', 'Sent Mbit/s', 'Responses', 'Response Mbit/s']);
      if (process.env.SCREENSHOT_DIR) {
        fs.mkdirSync(process.env.SCREENSHOT_DIR, {recursive: true});
        await page.screenshot({path: path.join(process.env.SCREENSHOT_DIR, summary.protocol + '-quality.png')});
      }
      for (const width of [800, 390, 320]) {
        await page.setViewportSize({width, height: 844});
        await page.waitForFunction(() => {
          const chart = document.getElementById('sample-quality');
          return chart.querySelector('canvas').getBoundingClientRect().width === chart.clientWidth;
        });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'No horizontal page overflow');
        assert.ok(await page.evaluate(() => [...document.querySelectorAll('#metrics dd')]
          .every(node => node.scrollWidth <= node.clientWidth)), `Metric values fit their columns at ${width}px`);
        assert.ok(await page.evaluate(() => {
          const values = [...document.querySelectorAll('#metrics dd')].map(node => node.getBoundingClientRect());
          const columns = innerWidth <= 760 ? 3 : 6;
          return values.every((rect, i) => Math.abs(rect.top - values[i - i % columns].top) < 1);
        }), `Metric values remain aligned when labels wrap at ${width}px`);
        assert.ok(await page.evaluate(() => {
          const canvas = document.querySelector('#sample-quality canvas');
          return canvas.width > 100 && canvas.height > 100;
        }));
        if (width === 390 && process.env.SCREENSHOT_DIR) {
          await page.screenshot({path: path.join(process.env.SCREENSHOT_DIR, summary.protocol + '-quality-mobile.png')});
        }
      }
      await page.setViewportSize({width: 1440, height: 1100});

      await page.locator('#open-diagnostics').click();
      assert.ok(await page.locator('#panel-diagnostics').isVisible());
      const diagnosticPng=await download('[data-chart-export="anomalies"]');
      assert.match(diagnosticPng.name,/-anomalies-/);
      await page.locator('#tab-latency').click();

      await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('rtt')).dispatchAction({type: 'dataZoom', start: 10, end: 90}));
      for (const tab of ['outcomes', 'sessions', 'diagnostics', 'recording', 'latency']) {
        await page.locator('#tab-' + tab).click();
        assert.ok(await page.locator('#panel-' + tab).isVisible());
        assert.equal(await page.locator('[role="tab"][aria-selected="true"]').count(), 1);
      }
      assert.equal(await page.locator('#anomalies canvas').count(), 1);
      assert.equal(await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('anomalies')).getOption().dataZoom[0].start), 10);
      assert.ok(await page.locator('#recordings tbody tr').count() > 0);
      assert.match(await page.locator('#run-details').innerText(), new RegExp(summary.run));
      await page.locator('#tab-latency').focus();
      await page.keyboard.press('ArrowRight');
      assert.ok(await page.locator('#panel-outcomes').isVisible());
      await page.keyboard.press('End');
      assert.ok(await page.locator('#panel-recording').isVisible());
      await page.keyboard.press('Home');
      assert.ok(await page.locator('#panel-latency').isVisible());

      // Replace only the parsed data block, keeping the production template and renderer.
      const html = fs.readFileSync(file, 'utf8');
      const fixture = structuredClone(data);
      fixture.extra.bad_headers = 0;
      fixture.metadata.complete = 'true';
      fixture.tables.summary = [{...summary, incomplete: 'false', response_timeout_status: 'available'}];
      fixture.tables.timeline = [[0, 0, 1], [80, 20, 1], [0, 100, 1], [100, 0, 1], [10, 10, 5]].map(([samples, timeouts, width], i) => ({
        ...points[0], start_s: String(i * 5), end_s: String(i * 5 + width), bucket_s: String(width),
        rtt_samples: String(samples), timeout_s: String(timeouts / width), sent_pps: '0',
        late_s: '20', duplicate_s: '30', canceled_s: '40'
      }));
      const loadFixture = async (timeline = true) => {
        const json = JSON.stringify(fixture).replaceAll('<', '\\u003c').replaceAll('>', '\\u003e').replaceAll('&', '\\u0026');
        await page.setContent(html.replace(payload, () => json));
        assert.equal(await page.locator('#render-error').textContent(), '');
        if (!timeline) return;
        return page.evaluate(() => echarts.getInstanceByDom(document.getElementById('sample-quality')).getOption().series[1].data.map(p => p[1]));
      };
      assert.deepEqual(await loadFixture(), [null, 20, 100, 0, 50]);
      const tooltip = await page.evaluate(() => {
        const c = echarts.getInstanceByDom(document.getElementById('rtt'));
        return c.getOption().tooltip[0].formatter([{dataIndex: 1, seriesName: 'Avg', value: [5, 1]}]);
      });
      assert.match(tooltip, /Valid RTT samples: 80/);
      assert.match(tooltip, /Timeouts: 20/);
      assert.match(tooltip, /20%/);
      assert.match(tooltip, /fewer than 100 samples/);
      fixture.tables.summary[0].incomplete = 'true';
      assert.deepEqual(await loadFixture(), [null, null, null, null, null]);
      assert.match(await page.locator('#sample-quality').getAttribute('title'), /unavailable/);
      assert.match(await page.locator('#anomaly-summary').innerText(), /INCOMPLETE/);
      assert.doesNotMatch(await page.locator('#anomaly-summary').innerText(), /No recorded anomalies/);
      assert.deepEqual(await page.locator('#attainment tbody tr td:nth-child(4)').allTextContents(),['-','-','-']);
      if(attainment.length){
        const partialAttainment=await download('#export-attainment');
        assert.ok(parse(partialAttainment.bytes,{columns:true}).every(row=>row.recording_status==='INCOMPLETE' && row.attainment_pct==='NA'));
      }
      const partialCsv=await download('#export-timeline');
      assert.ok(parse(partialCsv.bytes,{columns:true}).every(row=>row.recording_status==='INCOMPLETE' && row.request_accounting_status==='incomplete_recording'));
      fixture.tables.summary[0].incomplete = 'false';
      fixture.tables.summary[0].response_timeout_status = 'unresolved_sent';
      assert.deepEqual(await loadFixture(), [null, null, null, null, null]);
      assert.match(await page.locator('#anomaly-summary').innerText(), /Request accounting\s+unresolved_sent/);

      fixture.tables.summary[0].response_timeout_status = 'available';
      const second = {...fixture.tables.summary[0], run: '18446744073709551615', protocol: 'udp'};
      fixture.tables.summary.push(second);
      const otherPoints = fixture.tables.timeline.map(p => ({...p, run: second.run, protocol: second.protocol, rtt_samples: '123', timeout_s: '0'}));
      fixture.tables.timeline.push(...otherPoints);
      await loadFixture();
      await page.locator('#tab-diagnostics').click();
      await page.locator('#run').selectOption('1');
      assert.equal(await page.locator('#render-error').textContent(), '');
      assert.equal(await page.locator('#panel-diagnostics').isVisible(), true);
      assert.deepEqual(await page.evaluate(() => echarts.getInstanceByDom(document.getElementById('sample-quality')).getOption().series[0].data.map(p => p[1])), otherPoints.map(() => 123));
      assert.match(await page.locator('#run-details').innerText(), /18446744073709551615/);
      assert.ok(await page.locator('#export-attainment').isDisabled());
      assert.match(await page.locator('#attainment').innerText(),/Ready sampling unavailable/);
      assert.ok(!(await page.evaluate(()=>echarts.getInstanceByDom(document.getElementById('sessions')).getOption().series.map(series=>series.name))).includes('Ready'));
      const otherCsv=await download('#export-timeline');
      assert.ok(otherCsv.name.includes(second.run));
      assert.deepEqual(parse(otherCsv.bytes,{columns:true}).map(row=>row.run),otherPoints.map(()=>second.run));
      await page.locator('#run').selectOption('0');
      assert.equal(await page.locator('#render-error').textContent(), '');

      const saved=structuredClone(fixture.tables.summary[0]);
      for(const key of ['failed','timeout','limited','skipped','session_skipped','late','duplicate','reordered','invalid','canceled','error','unresolved_sent_unique'])fixture.tables.summary[0][key]='0';
      await loadFixture();
      assert.match(await page.locator('#anomaly-summary').innerText(), /No recorded anomalies/);
      fixture.tables.summary[0].limited='7';fixture.tables.summary[0].skipped='11';
      fixture.tables.summary[0].session_skipped='13';fixture.tables.summary[0].failed='18446744073709551615';
      await loadFixture();
      assert.match(await page.locator('#anomaly-summary').innerText(), /Local limited\s+7/);
      assert.match(await page.locator('#anomaly-summary').innerText(), /Skipped requests\s+11/);
      assert.match(await page.locator('#anomaly-summary').innerText(), /Skipped session slots\s+13/);
      assert.match(await page.locator('#anomaly-summary').innerText(), /18,446,744,073,709,551,615/);
      assert.doesNotMatch(await page.locator('#anomaly-summary').innerText(), /No recorded anomalies/);
      fixture.tables.summary[0]=structuredClone(saved);
      fixture.tables.summary[0].failed='NA';await loadFixture();
      assert.match(await page.locator('#anomaly-summary').innerText(), /Counters\s+Unavailable/);
      fixture.tables.summary[0]=structuredClone(saved);
      fixture.tables.summary[0].export_test='quoted "value", with\r\na newline';await loadFixture();
      const quotedCsv=await download('#export-summary');
      assert.equal(parse(quotedCsv.bytes,{columns:true})[0].export_test,fixture.tables.summary[0].export_test);
      await page.evaluate(()=>{
        const chart=echarts.getInstanceByDom(document.getElementById('rtt'));
        chart.getDataURL=()=>{throw new Error('synthetic encoding failure');};
      });
      await page.locator('[data-chart-export="rtt"]').click();
      assert.match(await page.locator('#export-status').textContent(), /Export failed: synthetic encoding failure/);
      assert.equal(await page.locator('[data-chart-export="rtt"]').isDisabled(),false);
      assert.equal(await page.locator('#render-error').textContent(),'');

      fixture.mode = 'summary';
      fixture.tables.timeline = [];
      delete fixture.tables.summary[0].response_timeout_status;
      await loadFixture(false);
      assert.equal(await page.locator('#status').textContent(), 'SUMMARY');
      assert.equal(await page.locator('canvas').count(), 0);
      assert.ok(await page.locator('#no-series').isVisible());
      assert.ok(await page.locator('#export-timeline').isDisabled());
      const aggregateCsv=await download('#export-summary');
      assert.deepEqual(parse(aggregateCsv.bytes,{columns:true}),[{...fixture.tables.summary[0],recording_status:'SUMMARY',request_accounting_status:'unavailable'}]);
      for (const tab of ['outcomes', 'sessions', 'diagnostics', 'recording', 'latency']) {
        await page.locator('#tab-' + tab).click();
        assert.ok(await page.locator('#panel-' + tab).isVisible());
      }
      assert.equal(await page.locator('#anomaly-section').isVisible(), false);
      console.log('PASS', summary.protocol, 'offline matrix, tabs, responsive layout, accounting, anomalies, LOAD attainment, run isolation and PNG/CSV exports');
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
  } finally {await browser.close();}
})().catch(e => {console.error(e); process.exitCode = 1;});
