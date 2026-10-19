const {test,expect}=require('./fixtures.cjs');
test('spacious layouts show route details and remain usable in both themes',async({page},testInfo)=>{
 page.on('pageerror',error=>{throw error});
 await page.addInitScript(()=>{window.cspViolations=[];document.addEventListener('securitypolicyviolation',event=>window.cspViolations.push(event.violatedDirective));});
 await page.route('**/api/config',async route=>{
  const response=await route.fetch();const config=await response.json();
  config.routes=[{id:'layout-app',name:'Customer portal',host:'portal.example.com',path:'/',enabled:true,preserveHost:true,upstreams:['https://portal.internal:8443','https://portal-backup.internal:8443'],excludedRuleIds:[],wafMode:'inherit',access:'internal',allowedMethods:[],botDenyPatterns:[],denyCIDRs:[],allowCIDRs:[],geoDenyCountries:[],geoAllowCountries:[]}];
  await route.fulfill({response,json:config});
 });
 await page.route('**/api/upstreams',route=>route.fulfill({json:[{route:'layout-app',healthy:true,lastCheck:new Date().toISOString()},{route:'layout-app',healthy:false,lastCheck:new Date().toISOString()}]}));
 await page.route('**/api/analytics',route=>route.fulfill({json:{routes:{'Customer portal':700,'Documentation':200,'API':100},statuses:{'2xx':700,'3xx':100,'4xx':150,'5xx':50}}}));
 await page.route('**/api/status',async route=>{
  const response=await route.fetch(),status=await response.json();
  status.requests=1000;status.blocked=90;status.detected=12;
  status.capacity={requests:32,requestLimit:128,upgrades:8,upgradeLimit:128,reservedBytes:67108864,budgetBytes:268435456};
  status.series=status.series.map((bucket,i)=>({...bucket,requests:10+(i*7)%30,blocked:i%7===0?4:0}));
  await route.fulfill({response,json:status});
 });
 await page.setViewportSize({width:1440,height:1050});
 await page.goto('/');
 await expect(page.getByRole('heading',{name:'Protection details'})).toBeVisible();
 await expect(page.getByLabel('Inspection buffers')).toBeVisible();
 await expect(page.getByRole('heading',{name:'Response mix'})).toBeVisible();
 await expect(page.locator('.chart-key')).toContainText('70.0%');
 await expect(page.getByLabel('Customer portal: 700 requests')).toHaveAttribute('value','700');
 await expect(page.getByLabel('HTTP requests: 25.0% used')).toBeVisible();
 expect(await page.evaluate(()=>window.cspViolations)).toEqual([]);
 await page.screenshot({path:testInfo.outputPath('overview-dark.png'),fullPage:true});
 await page.getByRole('link',{name:'Proxy Hosts',exact:true}).click();
 const card=page.getByRole('article',{name:'Customer portal'});
 await expect(card.getByText('Degraded',{exact:true})).toBeVisible();
 await expect(card.getByText('Internal only',{exact:true})).toBeVisible();
 await expect(card.getByText('1 / 2 healthy',{exact:true})).toBeVisible();
 await page.screenshot({path:testInfo.outputPath('routes-dark.png'),fullPage:true});
 await card.getByRole('button',{name:'Edit',exact:true}).click();
 await expect(page.getByRole('dialog')).toBeVisible();
 await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.getByRole('button',{name:'Switch to light theme'}).click();
 await page.screenshot({path:testInfo.outputPath('routes-light.png'),fullPage:true});
 for(const width of [390,768,1280]){
  await page.setViewportSize({width,height:900});
  for(const name of ['Overview','Proxy Hosts','WAF protection','Custom rules','Events','Users','OIDC','Certificates','Settings']){
   await page.getByRole('link',{name,exact:true}).first().click();
   await expect(page.locator('#main')).toHaveAttribute('data-page',({Overview:'overview','Proxy Hosts':'routes','WAF protection':'security','Custom rules':'rules',Events:'events',Users:'users',OIDC:'oidc',Certificates:'tls',Settings:'settings'})[name]);
   expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} at ${width}px`).toBeTruthy();
   if(width===1280&&['WAF protection','Users','OIDC','Settings','Custom rules'].includes(name))await page.screenshot({path:testInfo.outputPath(`${name.replaceAll(' ','-')}-desktop.png`),fullPage:true});
   if(width===390&&['Overview','Proxy Hosts','WAF protection','Users','OIDC','Settings','Custom rules'].includes(name))await page.screenshot({path:testInfo.outputPath(`${name.replaceAll(' ','-')}-mobile.png`),fullPage:true});
  }
 }
});
