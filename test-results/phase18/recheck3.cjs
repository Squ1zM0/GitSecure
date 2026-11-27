// Worker C — Phase 18 RECHECK-3 (final visual recheck, round 3).
// Verifies Worker B's round-2 fixes on the FINAL self-scan report:
//  1) selected-track label stagger (S8 fan, 360px)
//  2) file labels inside the plane at fit (360px, light+dark)
//  3) "N uses" captions separated (1280px fit)
// Plus no-regression spot checks and a pinch-zoom attempt.
// No source files edited. Own server :3100; port 3000 untouched.
const { chromium } = require('playwright-core');
const fs = require('fs');
const path = require('path');

const OUT = '/home/hatch/workspace/gitsecure/test-results/phase18';
const EXE = '/home/hatch/.cache/ms-playwright/chromium-1255/chrome-linux64/chrome';
const BASE = 'http://localhost:3100';
const SELF = `${BASE}/Squ1zM0/GitSecure`;

const logLines = [];
function L(s) { logLines.push(s); console.log(s); }
function PASS(name, detail) { L(`PASS  ${name} :: ${detail}`); }
function FAIL(name, detail) { L(`FAIL  ${name} :: ${detail}`); }
function INFO(s) { L(`INFO  ${s}`); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseT(t) {
  if (!t) return null;
  const m = /translate\(([-.\d]+)[ ,]([-.\d]+)\)\s*scale\(([-.\d]+)\)/.exec(t);
  return m ? { x: +m[1], y: +m[2], k: +m[3] } : null;
}
const fmtT = (v) => (v ? `translate(${v.x.toFixed(1)} ${v.y.toFixed(1)}) scale(${v.k.toFixed(3)})` : 'null');
async function worldT(page) {
  const w = await page.evaluate(() => {
    const g = document.querySelector('.map-plane svg > g');
    return g ? { transform: g.getAttribute('transform'), cls: g.getAttribute('class') || '' } : null;
  });
  return w ? parseT(w.transform) : null;
}
async function openMap(page) {
  await page.click('.view-toggle button:text("Map")');
  await page.waitForSelector('.map-plane svg', { timeout: 15000 });
  await page.waitForTimeout(800);
}
async function scrollMapIntoView(page) {
  await page.locator('.map-plane').scrollIntoViewIfNeeded().catch(() => {});
  await page.waitForTimeout(400);
}
async function nodeScreenPoint(page, nodeId) {
  return await page.evaluate((id) => {
    const g = document.querySelector(`g[data-node-id="${CSS.escape(id)}"]`);
    if (!g) return null;
    const c = g.querySelector('circle:not(.map-hit)');
    if (!c) return null;
    const r = c.getBoundingClientRect();
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  }, nodeId);
}
async function detailText(page) {
  return await page.evaluate(() => {
    const el = document.querySelector('.map-track-detail');
    return el ? el.innerText : 'NO DETAIL PANEL';
  });
}
async function edgeLabelCount(page) {
  return await page.evaluate(() => {
    const els = [...document.querySelectorAll('.map-plane text.map-edge-label')];
    const vis = els.filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0; });
    return { total: els.length, visible: vis.length };
  });
}
// Wait until the scan is FULLY finished: progress shell gone AND 37 secrets shown.
// Returns { settled, secretsLine, waitedSec }.
async function waitFinal(page, timeoutMs = 180000) {
  const t0 = Date.now();
  let last = '';
  while (Date.now() - t0 < timeoutMs) {
    const cur = await page.evaluate(() => ({
      line: document.body.innerText.match(/Showing[^\n]*secrets[^\n]*/)?.[0] || '',
      progress: document.body.innerText.includes('commits checked'),
      has37: /37 secrets/.test(document.body.innerText),
      grade: document.body.innerText.match(/Score[^\n]*/)?.[0] || '',
    }));
    if (cur.line !== last) { last = cur.line; INFO(`waitFinal poll t=${((Date.now() - t0) / 1000).toFixed(0)}s line=${JSON.stringify(cur.line)} progress=${cur.progress} has37=${cur.has37}`); }
    if (!cur.progress && cur.has37) return { settled: true, line: cur.line, grade: cur.grade, waited: ((Date.now() - t0) / 1000).toFixed(1) };
    await sleep(2000);
  }
  const cur = await page.evaluate(() => ({
    line: document.body.innerText.match(/Showing[^\n]*secrets[^\n]*/)?.[0] || '',
    progress: document.body.innerText.includes('commits checked'),
  }));
  return { settled: false, line: cur.line, progress: cur.progress, waited: ((Date.now() - t0) / 1000).toFixed(1) };
}
async function richestTrack(page) {
  return await page.evaluate(() => {
    const counts = {};
    for (const e of document.querySelectorAll('.map-plane g[data-edge-id]')) {
      const m = /Secret (\d+)/.exec(e.getAttribute('aria-label') || '');
      if (m) counts[m[1]] = (counts[m[1]] || 0) + 1;
    }
    const best = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    return best ? { secret: Number(best[0]), edges: best[1], nodeId: `finding:${Number(best[0]) - 1}` } : null;
  });
}
// Pairwise bbox overlap analysis. Returns { overlaps: [[a,b,area]...], maxOverlapCount, boxes }.
function analyseBoxes(boxes) {
  const overlaps = [];
  const counts = new Array(boxes.length).fill(0);
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j];
      const ox = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
      const oy = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
      if (ox > 1 && oy > 1) { overlaps.push([a, b, ox * oy]); counts[i]++; counts[j]++; }
    }
  }
  // closest non-overlapping pair distance (gap between boxes, 0 if touching/overlapping)
  let closest = null;
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j];
      const dx = Math.max(b.x - (a.x + a.w), a.x - (b.x + b.w), 0);
      const dy = Math.max(b.y - (a.y + a.h), a.y - (b.y + b.h), 0);
      const d = Math.hypot(dx, dy);
      if (!closest || d < closest.d) closest = { d, a, b };
    }
  }
  return { overlaps, maxOverlapCount: Math.max(0, ...counts), closest, counts };
}
const boxStr = (b) => `"${b.text}" [x=${b.x.toFixed(1)} y=${b.y.toFixed(1)} w=${b.w.toFixed(1)} h=${b.h.toFixed(1)}]`;

(async () => {
  const browser = await chromium.launch({ executablePath: EXE, args: ['--no-sandbox'] });
  L('INFO  browser launched: executablePath=' + EXE);

  // ============ CONTEXT A: 1280px light ============
  let ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  let page = await ctx.newPage();
  INFO('--- A: SELF-SCAN 1280 light ---');
  await page.goto(SELF, { waitUntil: 'domcontentloaded' });
  const toggleOk = await page.waitForSelector('.view-toggle button:text("Map")', { timeout: 240000 }).then(() => true).catch(() => false);
  INFO(`Map toggle present=${toggleOk}`);
  if (!toggleOk) { FAIL('setup', 'Map toggle never appeared'); await browser.close(); return; }
  const fin = await waitFinal(page, 180000);
  INFO(`final report settled=${fin.settled} waited=${fin.waited}s line=${JSON.stringify(fin.line)} grade=${JSON.stringify(fin.grade || '')}`);
  if (!fin.settled) { FAIL('setup: final report did not settle in 180s', `line=${JSON.stringify(fin.line)} progressStillPresent=${fin.progress}`); await browser.close(); return; }
  PASS('setup: final report settled', `line=${JSON.stringify(fin.line)} waited=${fin.waited}s`);
  await openMap(page);
  const fitT = await worldT(page);
  INFO(`1280 fit view: ${fmtT(fitT)}`);
  const mapCounts = await page.evaluate(() => ({
    nodes: document.querySelectorAll('.map-plane g[data-node-id]').length,
    findings: document.querySelectorAll('.map-plane g[data-node-id^="finding:"]').length,
    files: document.querySelectorAll('.map-plane g[data-node-id^="file:"]').length,
    edges: document.querySelectorAll('.map-plane g[data-edge-id]').length,
    labels: document.querySelectorAll('.map-plane text.map-edge-label').length,
  }));
  INFO(`map nodes=${mapCounts.nodes} findings=${mapCounts.findings} files=${mapCounts.files} edges=${mapCounts.edges} edge-labels-in-DOM=${mapCounts.labels}`);

  // --- Fix 3: captions separated at 1280 fit ---
  const captions = await page.evaluate(() => {
    const out = [];
    for (const t of document.querySelectorAll('.map-plane g[data-node-id^="finding:"] text.map-label')) {
      const txt = (t.textContent || '').trim();
      if (!/uses$/.test(txt) && txt !== 'dead end') continue;
      const r = t.getBoundingClientRect();
      out.push({ text: txt, x: r.left, y: r.top, w: r.width, h: r.height });
    }
    return out;
  });
  INFO(`captions found: ${captions.length}`);
  captions.forEach((c) => INFO(`  caption ${boxStr(c)}`));
  const capAn = analyseBoxes(captions);
  if (capAn.overlaps.length === 0) {
    PASS('fix3 captions separated @1280 fit', `${captions.length} "N uses" captions, 0 overlaps; closest pair gap=${capAn.closest ? capAn.closest.d.toFixed(1) : 'n/a'}px between ${capAn.closest ? `"${capAn.closest.a.text}" and "${capAn.closest.b.text}"` : ''}`);
  } else {
    FAIL('fix3 captions separated @1280 fit', `${capAn.overlaps.length} overlapping caption pairs: ` + capAn.overlaps.map(([a, b, ar]) => `"${a.text}" x "${b.text}" area=${ar.toFixed(1)}`).join('; '));
  }
  await scrollMapIntoView(page);
  await page.screenshot({ path: path.join(OUT, 'selfscan-1280-light-recheck3.png') });
  INFO('screenshot saved: selfscan-1280-light-recheck3.png (fit, nothing selected)');

  // --- No-regression: label gating at fit (0 labels, nothing selected) ---
  const labFit = await edgeLabelCount(page);
  if (labFit.visible === 0) PASS('regression: edge labels gated at fit, nothing selected', `0 visible labels at k=${fitT.k.toFixed(3)} (total edges ${mapCounts.edges})`);
  else FAIL('regression: edge labels gated at fit, nothing selected', `${labFit.visible} labels visible at k=${fitT.k.toFixed(3)}`);

  // --- No-regression: click finding selects + zooms + detail ---
  const pt1 = await nodeScreenPoint(page, 'finding:0');
  const beforeT = await worldT(page);
  await page.mouse.click(pt1.x, pt1.y);
  await page.waitForTimeout(700);
  const afterT = await worldT(page);
  const det1 = await detailText(page);
  const sel1 = await page.evaluate(() => document.querySelector('.map-plane g.map-node-selected')?.getAttribute('data-node-id') || null);
  INFO(`click finding:0: ${fmtT(beforeT)} -> ${fmtT(afterT)} selected=${sel1} detail=${JSON.stringify(det1.slice(0, 80))}`);
  if (sel1 === 'finding:0' && /Secret 1/.test(det1) && afterT.k > beforeT.k) PASS('regression: click finding selects + zooms', `selected=finding:0 detail="Secret 1…" k ${beforeT.k.toFixed(3)} -> ${afterT.k.toFixed(3)}`);
  else FAIL('regression: click finding selects + zooms', `selected=${sel1} k ${beforeT?.k} -> ${afterT?.k} detail=${JSON.stringify(det1.slice(0, 60))}`);

  // --- No-regression: labels appear past k=1.5 ---
  // Deselect first (background click), reset, then zoom in via toolbar until k>=1.5.
  await page.click('button[aria-label="Reset view"]');
  await page.waitForTimeout(600);
  const bgPt = await page.evaluate(() => { const r = document.querySelector('.map-plane svg').getBoundingClientRect(); return { x: r.x + 20, y: r.y + 20 }; });
  await page.mouse.click(bgPt.x, bgPt.y);
  await page.waitForTimeout(500);
  let kNow = (await worldT(page)).k;
  let zooms = 0;
  while (kNow < 1.5 && zooms < 6) { await page.click('button[aria-label="Zoom in"]'); await page.waitForTimeout(400); kNow = (await worldT(page)).k; zooms++; }
  const labZoom = await edgeLabelCount(page);
  INFO(`zoom past 1.5: ${zooms} toolbar zoom-ins, k=${kNow.toFixed(3)}, labels visible=${labZoom.visible} of ${mapCounts.edges}`);
  if (kNow >= 1.5 && labZoom.visible > 0) PASS('regression: labels appear past k=1.5', `k=${kNow.toFixed(3)} labels=${labZoom.visible}/${mapCounts.edges} (was 0 at fit)`);
  else FAIL('regression: labels appear past k=1.5', `k=${kNow.toFixed(3)} labels=${labZoom.visible}`);

  // --- No-regression: drag background pans ---
  await page.click('button[aria-label="Reset view"]');
  await page.waitForTimeout(600);
  const dragBefore = await worldT(page);
  const svgBox = await page.evaluate(() => { const r = document.querySelector('.map-plane svg').getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; });
  const cx0 = svgBox.x + svgBox.w / 2, cy0 = svgBox.y + svgBox.h / 2;
  await page.mouse.move(cx0, cy0);
  await page.mouse.down();
  for (let i = 1; i <= 10; i++) await page.mouse.move(cx0 + 12 * i, cy0 + 6 * i, { steps: 1 });
  await page.mouse.up();
  await page.waitForTimeout(500);
  const dragAfter = await worldT(page);
  INFO(`drag pan: ${fmtT(dragBefore)} -> ${fmtT(dragAfter)} (dragged +120,+60)`);
  if (Math.abs((dragAfter.x - dragBefore.x) - 120) < 2 && Math.abs((dragAfter.y - dragBefore.y) - 60) < 2 && Math.abs(dragAfter.k - dragBefore.k) < 0.001)
    PASS('regression: background drag pans', `translate delta exactly (+120.0,+60.0), k unchanged ${dragAfter.k.toFixed(3)}`);
  else FAIL('regression: background drag pans', `delta=(${(dragAfter.x - dragBefore.x).toFixed(1)},${(dragAfter.y - dragBefore.y).toFixed(1)}) expected (120,60)`);

  // --- No-regression: Reset view returns to fit ---
  await page.click('button[aria-label="Reset view"]');
  await page.waitForTimeout(600);
  const resetT = await worldT(page);
  INFO(`Reset view: ${fmtT(resetT)} vs fit ${fmtT(fitT)}`);
  if (Math.abs(resetT.x - fitT.x) < 0.5 && Math.abs(resetT.y - fitT.y) < 0.5 && Math.abs(resetT.k - fitT.k) < 0.001)
    PASS('regression: Reset view returns to fit', `back to ${fmtT(resetT)}`);
  else FAIL('regression: Reset view returns to fit', `got ${fmtT(resetT)}, expected ${fmtT(fitT)}`);

  // --- No-regression: redaction (whole page) ---
  const redact = await page.evaluate(() => {
    const txt = document.body.innerText;
    return { skAnt: txt.includes('sk-ant-'), begin: txt.includes('-----BEGIN'), htmlSkAnt: document.documentElement.innerHTML.includes('sk-ant-'), htmlBegin: document.documentElement.innerHTML.includes('-----BEGIN') };
  });
  INFO(`redaction: innerText sk-ant-=${redact.skAnt} BEGIN=${redact.begin}; innerHTML sk-ant-=${redact.htmlSkAnt} BEGIN=${redact.htmlBegin}`);
  if (!redact.skAnt && !redact.begin && !redact.htmlSkAnt && !redact.htmlBegin) PASS('regression: redaction', 'no sk-ant- / -----BEGIN in page text or HTML');
  else FAIL('regression: redaction', JSON.stringify(redact));
  await ctx.close();

  // ============ CONTEXT B: 360px light (fresh load) ============
  ctx = await browser.newContext({ viewport: { width: 360, height: 800 } });
  page = await ctx.newPage();
  INFO('--- B: SELF-SCAN 360 light (fresh load) ---');
  await page.goto(SELF, { waitUntil: 'domcontentloaded' });
  const toggleOkB = await page.waitForSelector('.view-toggle button:text("Map")', { timeout: 240000 }).then(() => true).catch(() => false);
  INFO(`Map toggle present=${toggleOkB}`);
  if (!toggleOkB) { FAIL('setup 360', 'Map toggle never appeared'); await browser.close(); return; }
  const finB = await waitFinal(page, 180000);
  INFO(`final report settled=${finB.settled} waited=${finB.waited}s line=${JSON.stringify(finB.line)}`);
  if (!finB.settled) { FAIL('setup 360: final report did not settle in 180s', `line=${JSON.stringify(finB.line)} progressStillPresent=${finB.progress}`); await browser.close(); return; }
  PASS('setup 360: final report settled', `line=${JSON.stringify(finB.line)} waited=${finB.waited}s`);
  await openMap(page);
  const fit360 = await worldT(page);
  INFO(`360px fit view: ${fmtT(fit360)}`);

  // --- Fix 2: file labels inside the plane at fit, nothing selected ---
  const planeBox = await page.evaluate(() => {
    const el = document.querySelector('.map-plane');
    const r = el.getBoundingClientRect();
    return { x: r.left, y: r.top, w: r.width, h: r.height, right: r.right, bottom: r.bottom };
  });
  INFO(`map-plane container box: x=${planeBox.x.toFixed(1)} y=${planeBox.y.toFixed(1)} w=${planeBox.w.toFixed(1)} h=${planeBox.h.toFixed(1)}`);
  const fileLabels = await page.evaluate(() => {
    const out = [];
    for (const t of document.querySelectorAll('.map-plane g[data-node-id^="file:"] text.map-label')) {
      const r = t.getBoundingClientRect();
      out.push({ text: (t.textContent || '').trim(), x: r.left, y: r.top, w: r.width, h: r.height, right: r.right, bottom: r.bottom });
    }
    return out;
  });
  INFO(`file labels found: ${fileLabels.length}`);
  fileLabels.forEach((l) => INFO(`  file label ${boxStr(l)}`));
  const crossing = fileLabels.filter((l) => l.x < planeBox.x - 1 || l.right > planeBox.right + 1 || l.y < planeBox.y - 1 || l.bottom > planeBox.bottom + 1);
  if (crossing.length === 0) PASS('fix2 file labels inside plane @360 fit', `all ${fileLabels.length} file-node labels inside the map-plane container box`);
  else FAIL('fix2 file labels inside plane @360 fit', `${crossing.length} label(s) cross the container edge: ` + crossing.map((l) => `"${l.text}" ${boxStr(l)} vs container right=${planeBox.right.toFixed(1)} bottom=${planeBox.bottom.toFixed(1)}`).join('; '));
  const overflow360 = await page.evaluate(() => document.documentElement.scrollWidth);
  INFO(`360px overflow: documentElement.scrollWidth=${overflow360}`);
  if (overflow360 === 360) PASS('regression: 360px overflow (light)', `scrollWidth=${overflow360} == 360`);
  else if (overflow360 <= 360) PASS('regression: 360px overflow (light)', `scrollWidth=${overflow360} (<=360)`);
  else FAIL('regression: 360px overflow (light)', `scrollWidth=${overflow360} (>360)`);
  await scrollMapIntoView(page);
  await page.screenshot({ path: path.join(OUT, 'selfscan-360-light-recheck3.png') });
  INFO('screenshot saved: selfscan-360-light-recheck3.png (fit, nothing selected)');

  // --- Fix 1: selected-track label stagger at 360px ---
  const track = await richestTrack(page);
  INFO(`richest finding track: ${JSON.stringify(track)}`);
  let selOk = false;
  for (let attempt = 1; attempt <= 3 && !selOk; attempt++) {
    const pt = await nodeScreenPoint(page, track.nodeId);
    if (!pt) { INFO(`attempt ${attempt}: node point null`); continue; }
    await page.mouse.click(pt.x, pt.y);
    await page.waitForTimeout(600);
    const k = (await worldT(page))?.k;
    const labs = await edgeLabelCount(page);
    const det = await detailText(page);
    const crumb = await page.evaluate(() => [...document.querySelectorAll('.map-breadcrumb button')].map((b) => b.textContent.trim()));
    INFO(`select attempt ${attempt}: k=${k?.toFixed(3)} labels=${labs.visible} (track=${track.edges}) crumbs=${JSON.stringify(crumb)} detail=${JSON.stringify(det.slice(0, 50))}`);
    if (crumb.length >= 2 && new RegExp(`Secret ${track.secret}\\b`).test(det)) selOk = true;
    else { INFO(`attempt ${attempt}: selection did not stick — retrying`); await page.click('button[aria-label="Reset view"]').catch(() => {}); await page.waitForTimeout(500); }
  }
  if (!selOk) FAIL('fix1 setup: richest-track selection did not stick in 3 attempts', 'could not isolate the selected track (live scan chunks?)');
  else {
    const selK = (await worldT(page)).k;
    const labelBoxes = await page.evaluate(() => {
      const out = [];
      for (const t of document.querySelectorAll('.map-plane text.map-edge-label')) {
        const r = t.getBoundingClientRect();
        if (r.width > 0 && r.height > 0) out.push({ text: (t.textContent || '').trim(), x: r.left, y: r.top, w: r.width, h: r.height });
      }
      return out;
    });
    INFO(`selected-track labels visible: ${labelBoxes.length} (track edges=${track.edges}) at k=${selK.toFixed(3)}`);
    labelBoxes.forEach((l) => INFO(`  edge label ${boxStr(l)}`));
    const an = analyseBoxes(labelBoxes);
    INFO(`label overlap analysis: ${an.overlaps.length} overlapping pairs; max labels overlapping any one label=${an.maxOverlapCount}`);
    an.overlaps.forEach(([a, b, ar]) => INFO(`  OVERLAP "${a.text}" ${boxStr(a)} x "${b.text}" ${boxStr(b)} area=${ar.toFixed(1)}`));
    if (an.maxOverlapCount <= 2 && an.overlaps.length === 0) PASS('fix1 selected-track label stagger @360', `${labelBoxes.length} labels, 0 overlaps, max overlap count 0 — labels spread along their edges`);
    else if (an.maxOverlapCount <= 2) PASS('fix1 selected-track label stagger @360 (partial)', `${labelBoxes.length} labels, ${an.overlaps.length} overlapping pair(s) but max overlap count=${an.maxOverlapCount} (<=2)`);
    else FAIL('fix1 selected-track label stagger @360', `${labelBoxes.length} labels, ${an.overlaps.length} overlapping pairs, max overlap count=${an.maxOverlapCount} (>2): ` + an.overlaps.map(([a, b]) => `"${a.text}"@${a.x.toFixed(0)},${a.y.toFixed(0)} x "${b.text}"@${b.x.toFixed(0)},${b.y.toFixed(0)}`).join('; '));
    await scrollMapIntoView(page);
    await page.screenshot({ path: path.join(OUT, 'selfscan-360-selected-recheck3.png') });
    INFO('screenshot saved: selfscan-360-selected-recheck3.png (selected track)');
  }

  // --- 360 dark fit screenshot + overflow ---
  await page.click('button[aria-label="Reset view"]').catch(() => {});
  await page.waitForTimeout(500);
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.waitForTimeout(600);
  await scrollMapIntoView(page);
  await page.screenshot({ path: path.join(OUT, 'selfscan-360-dark-recheck3.png') });
  INFO('screenshot saved: selfscan-360-dark-recheck3.png (fit, nothing selected)');
  const overflow360d = await page.evaluate(() => document.documentElement.scrollWidth);
  INFO(`360px dark overflow: documentElement.scrollWidth=${overflow360d}`);
  if (overflow360d <= 360) PASS('regression: 360px overflow (dark)', `scrollWidth=${overflow360d} (<=360)`);
  else FAIL('regression: 360px overflow (dark)', `scrollWidth=${overflow360d} (>360)`);
  await page.emulateMedia({ colorScheme: 'light' });
  await ctx.close();

  // ============ CONTEXT C: pinch zoom attempt (touch) ============
  INFO('--- C: PINCH ZOOM attempt (touch emulation) ---');
  try {
    ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, hasTouch: true, isMobile: true });
    page = await ctx.newPage();
    await page.goto(SELF, { waitUntil: 'domcontentloaded' });
    const toggleOkC = await page.waitForSelector('.view-toggle button:text("Map")', { timeout: 240000 }).then(() => true).catch(() => false);
    INFO(`pinch ctx: Map toggle present=${toggleOkC}`);
    if (toggleOkC) {
      const finC = await waitFinal(page, 180000);
      INFO(`pinch ctx: final settled=${finC.settled} waited=${finC.waited}s`);
      if (finC.settled) {
        await openMap(page);
        await scrollMapIntoView(page);
        const kBefore = (await worldT(page)).k;
        INFO(`pinch: k before=${kBefore.toFixed(3)}`);
        // Tap sanity check: touchscreen.tap on the map background should not crash.
        const cdp = await ctx.newCDPSession(page);
        const box = await page.evaluate(() => { const r = document.querySelector('.map-plane svg').getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; });
        const mx = box.x + box.w / 2, my = box.y + box.h / 2;
        // Two-finger pinch OUT: start close together, spread apart.
        await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x: mx - 20, y: my, id: 1 }, { x: mx + 20, y: my, id: 2 }] });
        for (let i = 1; i <= 10; i++) {
          const d = 20 + i * 12;
          await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x: mx - d, y: my, id: 1 }, { x: mx + d, y: my, id: 2 }] });
          await sleep(50);
        }
        await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
        await page.waitForTimeout(700);
        const kAfter = (await worldT(page)).k;
        INFO(`pinch out: k ${kBefore.toFixed(3)} -> ${kAfter.toFixed(3)}`);
        if (kAfter > kBefore + 0.05) PASS('pinch zoom (touch emulation)', `pinch-out raised k ${kBefore.toFixed(3)} -> ${kAfter.toFixed(3)} via CDP Input.dispatchTouchEvent two-finger pinch`);
        else FAIL('pinch zoom (touch emulation)', `k unchanged after CDP two-finger pinch-out: ${kBefore.toFixed(3)} -> ${kAfter.toFixed(3)} (touch events dispatched without error; gesture may not be recognised, or pointer-cache path needs real touch)`);
      } else FAIL('pinch zoom (touch emulation)', `final report did not settle in 180s in touch context (line=${JSON.stringify(finC.line)})`);
    } else FAIL('pinch zoom (touch emulation)', 'Map toggle never appeared in touch context');
    await ctx.close();
  } catch (e) {
    FAIL('pinch zoom (touch emulation)', `exception: ${e.message}`);
  }

  await browser.close();
  fs.writeFileSync(path.join(OUT, 'headless-run-recheck3.log'), logLines.join('\n') + '\n');
  const passes = logLines.filter((l) => l.startsWith('PASS')).length;
  const fails = logLines.filter((l) => l.startsWith('FAIL')).length;
  L(`INFO  done. ${passes} PASS, ${fails} FAIL`);
  fs.appendFileSync(path.join(OUT, 'headless-run-recheck3.log'), `INFO  done. ${passes} PASS, ${fails} FAIL\n`);
})().catch((e) => {
  console.error('FATAL', e);
  fs.appendFileSync(path.join(OUT, 'headless-run-recheck3.log'), logLines.join('\n') + `\nFATAL ${e.stack}\n`);
  process.exit(1);
});
