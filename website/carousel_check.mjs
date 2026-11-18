import {chromium, firefox} from 'playwright';
import AxeBuilder from '@axe-core/playwright';
import fs from 'node:fs';
import path from 'node:path';

const url = process.env.SITE_QA_URL || 'http://127.0.0.1:8767/volparossa/';
const output = process.env.SITE_QA_OUTPUT || '../.volparossa-dev/carousel-review';
const expected = ['code','image','cloud','browser','chat','mail','map','weather','studio'];
fs.mkdirSync(output, {recursive: true});
const results = [];
const check = (value, message) => { if (!value) throw new Error(message); };
const start = page => page.locator('[data-carousel]').getAttribute('data-start').then(Number);
const visibleNames = page => page.locator('.core-carousel-card:not([inert])').evaluateAll(nodes => nodes.map(n => n.dataset.app));
const scrollCarousel = async page => {
  await page.evaluate(() => document.querySelector('[data-carousel]').scrollIntoView({block:'center',behavior:'instant'}));
  await page.waitForTimeout(150);
  await page.mouse.move(0, 0);
};
const save = () => fs.writeFileSync(path.join(output,'carousel-results.json'), JSON.stringify(results,null,2)+'\n');

for (const [name,engine] of [['chromium',chromium],['firefox',firefox]]) {
  const browser = await engine.launch(name === 'chromium' ? {executablePath: process.env.CHROME_PATH || undefined,args:['--no-sandbox']} : {});
  try {
    for (const width of [320,390,768,1440,2560]) {
      const context = await browser.newContext({viewport:{width,height:1000}});
      try {
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        page.on('response', response => { if(response.status() >= 400) errors.push(`${response.status()} ${response.url()}`); });
        await page.goto(url,{waitUntil:'networkidle'});
        await page.evaluate(() => document.fonts.ready);
        await scrollCarousel(page);
        const allNames = await page.locator('.core-carousel-card').evaluateAll(nodes => nodes.map(n => n.dataset.app));
        check(JSON.stringify(allNames) === JSON.stringify(expected), `${name}/${width}: wrong application inventory`);
        const columns = width <=600 ? 1 : width <=1100 ? 2 : 3;
        const seen = new Set();
        for(let p=0;p<Math.ceil(9/columns);p++) {
          const visible = page.locator('.core-carousel-card:not([inert])');
          for(const app of await visibleNames(page))seen.add(app);
          check(await visible.count() <= columns, `${name}/${width}: visible count`);
          await page.waitForFunction(() => [...document.querySelectorAll('.core-carousel-card:not([inert]) img')].every(i => i.complete && i.naturalWidth > 0));
          check(await visible.locator('img').evaluateAll(images => images.every(i=>i.complete && i.naturalWidth >0)), `${name}/${width}: icon failed`);
          for(const link of await visible.locator('.core-carousel-explore').all())check((await link.getAttribute('href')).startsWith('https://github.com/VOLPAROSSA/volparossa-'),'Unpublished app lacks repository destination');
          check(await page.locator('.core-carousel-card[inert]').evaluateAll(nodes=>nodes.every(n=>n.getAttribute('aria-hidden')==='true')), 'Offscreen cards exposed');
          if (width===1440) {
            await page.waitForTimeout(700);
            await page.locator('#applications').screenshot({path:path.join(output,`${name}-applications-group-${p+1}.png`)});
          }
          await page.locator('[data-carousel-next]').click();
        }
        check(seen.size===9 && await start(page)===0, `${name}/${width}: navigation omitted apps or failed wrap`);
        await page.locator('[data-carousel-previous]').click();
        check(await start(page)===Math.floor(8/columns)*columns, `${name}/${width}: previous wrap`);
        await page.locator('[data-carousel-next]').click();
        const suppressedSwipe = await page.evaluate(() => {
          const viewport=document.querySelector('.core-carousel-viewport');
          const link=document.querySelector('.core-carousel-card:not([inert]) .core-carousel-explore');
          viewport.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,pointerType:'touch',clientX:230,clientY:100}));
          viewport.dispatchEvent(new PointerEvent('pointerup',{bubbles:true,pointerType:'touch',clientX:80,clientY:105}));
          return !link.dispatchEvent(new MouseEvent('click',{bubbles:true,cancelable:true}));
        });
        check(suppressedSwipe && await start(page)===columns, `${name}/${width}: swipe followed an application link`);
        await page.locator('[data-carousel-previous]').click();
        await page.locator('.core-carousel-card:not([inert]) .core-carousel-explore').last().focus();
        await page.keyboard.press('Tab');
        check(await page.evaluate(()=>!document.activeElement.closest('.core-carousel-card[inert]')),`${name}/${width}: keyboard entered offscreen card`);
        check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name}/${width}: document overflow`);
        if(width===390 || width===1440) {
          await page.waitForTimeout(700);
          const axe = await new AxeBuilder({page}).include('[data-carousel]').withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze();
          check(axe.violations.length===0, `${name}/${width}: accessibility ${JSON.stringify(axe.violations)}`);
          await page.locator('#applications').screenshot({path:path.join(output,`${name}-applications-${width}.png`)});
        }
        await page.evaluate(()=>{
          const values=[...document.querySelectorAll('body *')].map(n=>[n,parseFloat(getComputedStyle(n).fontSize)]);
          for(const [n,size] of values)n.style.fontSize=`${size*2}px`;
        });
        for(let p=0;p<Math.ceil(9/columns);p++) {
          await page.locator('[data-carousel-next]').click();
          await page.waitForTimeout(700);
          const overflow = await page.locator('.core-carousel-card:not([inert])').evaluateAll(nodes=>nodes.flatMap(card=>[...card.querySelectorAll('*')].filter(n=>{
            const r=n.getBoundingClientRect();const c=card.getBoundingClientRect();return r.width && (r.right>c.right+1 || r.left<c.left-1);
          }).map(n=>n.tagName+'.'+n.className)));
          check(!overflow.length,`${name}/${width}: text zoom clips card ${overflow.join(',')}`);
          check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name}/${width}: text zoom document overflow`);
        }
        check(!errors.length, `${name}/${width}: browser errors ${errors.join(', ')}`);
        results.push({browser:name,width,inventory9:true,allIconsLoaded:true,navigationWrap:true,textZoom200:true,swipeSuppressesClick:true,consoleAndHTTPErrorCount:errors.length});
        save();
      } finally {await context.close();}
    }
    const context=await browser.newContext({viewport:{width:1440,height:1000}});
    try {
      const page=await context.newPage();
      await page.clock.install();
      await page.goto(url,{waitUntil:'networkidle'});
      await scrollCarousel(page);
      await page.clock.fastForward(6200);
      check(await start(page)===3,`${name}: did not rotate automatically`);
      await page.locator('.core-carousel-card:not([inert]) h3').first().hover();
      const hovered=await start(page);
      await page.clock.fastForward(14000);
      check(await start(page)===hovered,`${name}: hover did not pause`);
      await page.mouse.move(0,0);
      await page.locator('.core-carousel-card:not([inert]) a').first().focus();
      await page.clock.fastForward(14000);
      check(await start(page)===hovered,`${name}: keyboard focus did not pause`);
      await page.locator('[data-carousel-rotation]').click();
      check(await page.locator('[data-carousel]').getAttribute('data-rotation')==='paused',`${name}: pause control`);
      await page.evaluate(()=>document.activeElement.blur());await page.mouse.move(0,0);
      await page.clock.fastForward(14000);
      check(await start(page)===hovered,`${name}: explicit pause did not hold`);
      await page.locator('[data-carousel-rotation]').click();
      await page.evaluate(()=>document.activeElement.blur());await page.mouse.move(0,0);
      await page.clock.fastForward(6500);
      check(await start(page)!==hovered,`${name}: explicit start did not resume`);
      await page.evaluate(()=>scrollTo({top:0,behavior:'instant'}));await page.waitForTimeout(150);
      const offscreen=await start(page);
      await page.clock.fastForward(14000);
      check(await start(page)===offscreen,`${name}: offscreen did not pause`);
      await page.emulateMedia({reducedMotion:'reduce'});
      await scrollCarousel(page);
      check(await page.locator('[data-carousel]').getAttribute('data-rotation')==='paused',`${name}: changing motion preference did not pause`);
      results.push({browser:name,automaticRotation:true,hoverPause:true,keyboardFocusPause:true,explicitPauseStart:true,offscreenPause:true,changedReducedMotionPause:true});save();
    } finally {await context.close();}
    const reduced=await browser.newContext({viewport:{width:390,height:900},reducedMotion:'reduce'});
    try {
      const page=await reduced.newPage();await page.clock.install();await page.goto(url,{waitUntil:'networkidle'});await scrollCarousel(page);
      await page.clock.fastForward(14000);check(await start(page)===0,`${name}: reduced motion autoplay`);
      check(await page.locator('.core-carousel-track').evaluate(n=>getComputedStyle(n).transitionDuration)==='0s',`${name}: reduced motion transition`);
      await page.locator('[data-carousel-next]').click();check(await start(page)===1,`${name}: reduced motion manual control`);
      results.push({browser:name,reducedMotionInitialPause:true,reducedMotionManualNavigation:true});save();
    } finally {await reduced.close();}
    const noJS=await browser.newContext({viewport:{width:390,height:900},javaScriptEnabled:false});
    try {
      const page=await noJS.newPage();await page.goto(url,{waitUntil:'networkidle'});
      check(await page.locator('.core-carousel-card').count()===9,`${name}: no-JS inventory`);
      check(await page.locator('.core-carousel-card[inert],.core-carousel-card[aria-hidden="true"]').count()===0,`${name}: no-JS cards hidden`);
      check(await page.locator('.core-carousel-controls').isHidden(),`${name}: no-JS inert controls visible`);
      for(const card of await page.locator('.core-carousel-card').all()) {
        await card.scrollIntoViewIfNeeded();check(await card.locator('a.core-carousel-explore').isVisible(),`${name}: no-JS link missing`);
      }
      results.push({browser:name,noJavaScriptAllNineReachable:true});save();
    } finally {await noJS.close();}
  } finally {await browser.close();}
}
console.log(`Carousel checks passed: ${results.length} browser/viewport and behavior groups. Reports: ${output}`);
