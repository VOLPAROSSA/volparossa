import {chromium, firefox} from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs';
import path from 'node:path';

const url = process.env.SITE_QA_URL || 'http://127.0.0.1:8765/volparossa/';
const output = process.env.SITE_QA_OUTPUT || '../.volparossa-dev/browser-review';
fs.mkdirSync(output, {recursive:true});
const results = [];
function check(value, message) { if (!value) throw Error(message); }
async function settle(page) {
  await page.evaluate(async () => {
    await document.fonts.ready;
    for (let y = 0; y < document.body.scrollHeight; y += 600) {
      scrollTo({top:y, behavior:'instant'});
      await new Promise(r => setTimeout(r, 70));
    }
    await Promise.all([...document.images].map(i => i.decode().catch(() => {})));
    scrollTo({top:0, behavior:'instant'});
  });
}
async function overflow(page) {
  return page.evaluate(() => ({width:innerWidth, scroll:document.documentElement.scrollWidth,
    offenders:[...document.querySelectorAll('main *, header *, footer *')].filter(e => {
      const r=e.getBoundingClientRect(); return r.width && (r.right>innerWidth+1 || r.left < -1);
    }).slice(0,10).map(e => e.tagName+'.'+e.className)}));
}
for (const [name, engine] of [['chromium',chromium],['firefox',firefox]]) {
  const browser = await engine.launch(name==='chromium' ? {executablePath:process.env.CHROME_PATH || undefined,args:['--no-sandbox']} : {});
  for (const width of [320,390,768,1440,1920,2560]) {
    const context = await browser.newContext({viewport:{width,height:900}});
    const page = await context.newPage();
    const errors=[], requests=[];
    page.on('pageerror',e => errors.push(e.message));
    page.on('response',r => {if(r.status()>=400)errors.push(r.status()+' '+r.url());});
    page.on('request',r => requests.push(r.url()));
    await page.goto(url,{waitUntil:'networkidle'});
    await settle(page);
    const dimensions=await overflow(page);
    check(dimensions.scroll <= width, `${name} ${width} overflow: ${JSON.stringify(dimensions)}`);
    check(await page.locator('img').evaluateAll(xs => xs.every(i => i.complete && i.naturalWidth)),`${name} ${width} image did not load`);
    check(!errors.length,`${name} ${width}: ${errors.join(', ')}`);
    check(requests.every(u=>new URL(u).origin===new URL(url).origin), 'Unexpected third-party visitor request');
    for(const layer of await page.locator('#layers details').all()) {
      await layer.locator('summary').focus();await page.keyboard.press('Enter');
      check(await layer.evaluate(e=>e.open),'Layer keyboard disclosure failed');
      check(await layer.locator('a').isVisible(),'Layer source link unavailable');
      await layer.locator('summary').press('Enter');
    }
    await page.locator('#dps details summary').click();
    check(await page.locator('#dps details').evaluate(e=>e.open),'DPS disclosure failed');
    check(await page.locator('#dps details').innerText().then(t=>t.includes('training models each need separate permission')),'DPS permissions unavailable');
    await page.locator('#dps details summary').click();
    if(width===390 || width===1440) {
      const axe=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa']).analyze();
      const violations=axe.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))}));
      results.push({browser:name,width,violations});
      // Preserve failures as evidence before exiting.
      fs.writeFileSync(path.join(output,'browser-results.json'),JSON.stringify(results,null,2));
      check(!violations.length,`${name} ${width} accessibility: ${JSON.stringify(violations)}`);
      await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));
      await page.screenshot({path:path.join(output,`${name}-${width}.png`),fullPage:true});
      for (const id of ['overview','intelligence','dps','contribute']) await page.locator('#'+id).screenshot({path:path.join(output,`${name}-${id}-${width}.png`)});
    }
    if(width===2560 && name==='firefox') {
      await page.screenshot({path:path.join(output,'firefox-2560.png'),fullPage:true});
      await page.locator('#overview').screenshot({path:path.join(output,'firefox-hero-2560.png')});
    }
    // Text-only zoom: double every computed font size without changing viewport.
    await page.evaluate(()=>{
      const sizes=[...document.querySelectorAll('body *')].map(e=>[e,parseFloat(getComputedStyle(e).fontSize)]);
      for(const [e,s] of sizes)e.style.fontSize=(s*2)+'px';
      scrollTo({top:0,behavior:'instant'});
    });
    const zoom=await overflow(page);
    check(zoom.scroll<=width,`${name} ${width} 200% text overflow: ${JSON.stringify(zoom)}`);
    const clearHeader=await page.evaluate(()=>document.querySelector('.core-hero h1').getBoundingClientRect().top>=document.querySelector('.site-header').getBoundingClientRect().bottom);
    check(clearHeader,`${name} ${width} header covers hero at 200% text`);
    if(width===390)await page.screenshot({path:path.join(output,`${name}-text-200.png`),fullPage:true});
    results.push({browser:name,width,normal:'pass',textResize200:'pass',consoleErrors:errors.length,thirdPartyRequests:0});
    await context.close();
  }
  const page=await browser.newPage({viewport:{width:390,height:844},reducedMotion:'reduce'});
  await page.goto(url,{waitUntil:'networkidle'});
  await page.keyboard.press('Tab');check(await page.locator('.skip-link').evaluate(e=>e===document.activeElement),'Skip link first');
  await page.keyboard.press('Enter');check(await page.locator('#main').evaluate(e=>e===document.activeElement),'Skip link target');
  await page.locator('.mobile-nav summary').click();check(await page.locator('.mobile-nav').evaluate(e=>e.open),'Menu opening');
  await page.keyboard.press('Escape');check(await page.locator('.mobile-nav').evaluate(e=>!e.open),'Menu Escape');
  check(await page.evaluate(()=>getComputedStyle(document.documentElement).scrollBehavior)==='auto','Reduced motion scroll');
  await page.getByRole('link',{name:'Explore the core',exact:false}).click();
  check(await page.locator('#layers-title').evaluate(e=>{const r=e.getBoundingClientRect();return r.top>=0&&r.top<innerHeight;}),'Hero anchor destination');
  await page.close();
  const nojs=await browser.newContext({javaScriptEnabled:false,viewport:{width:390,height:844}});
  const n=await nojs.newPage();await n.goto(url);
  await n.locator('.mobile-nav summary').click();check(await n.locator('.mobile-nav a[aria-current="page"]').isVisible(),'No-JS menu');
  await n.locator('.mobile-nav summary').click();await n.locator('#layers details').first().locator('summary').click();
  check(await n.locator('#layers details').first().locator('a').isVisible(),'No-JS layer documentation');
  await n.locator('#dps details summary').click();check(await n.locator('#dps details').evaluate(e=>e.open),'No-JS DPS details');
  await nojs.close();await browser.close();
}
fs.writeFileSync(path.join(output,'browser-results.json'),JSON.stringify(results,null,2));
console.log('PASS: Chromium and Firefox at six widths, 200% text, four axe scans, keyboard, no JavaScript, reduced motion, local-only requests and loaded artwork.');
