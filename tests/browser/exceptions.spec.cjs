const {test,expect}=require('@playwright/test');

test.beforeEach(async({page})=>{
 page.on('pageerror',error=>{throw error;});
 await page.goto('/');
 await page.getByLabel('Password',{exact:true}).fill('browser-test-admin-password');
 await page.getByRole('button',{name:'Sign in to Bastion'}).click();
 await expect(page.locator('#shell')).toBeVisible();
 const result=await page.evaluate(async()=>{
  const s=await (await fetch('/api/session')).json(),c=await (await fetch('/api/config')).json();
  c.exceptions=[];
  c.routes=[{id:'exception-host',name:'Editor application',host:'editor.example.com',path:'/',enabled:true,preserveHost:true,upstreams:['http://93.184.216.34'],excludedRuleIds:[]}];
  const r=await fetch('/api/config',{method:'PUT',headers:{'Content-Type':'application/json','X-CSRF-Token':s.csrf,'If-Match':String(c.revision)},body:JSON.stringify(c)});
  return {status:r.status,body:await r.text()};
 });
 expect(result.status,result.body).toBe(200);
 await page.goto('/#exceptions');await page.reload();
 await expect(page.getByRole('heading',{name:'Exceptions',exact:true})).toBeVisible();
});

test('central exception lifecycle, filters, persistence and mobile layout',async({page},testInfo)=>{
 await page.getByRole('button',{name:'Add exception',exact:true}).click();
 await page.getByLabel('Exception name',{exact:true}).fill('Editor markup');
 await page.getByLabel('Reason',{exact:true}).fill('Reviewed rich text submission');
 await page.getByLabel('Editor application · editor.example.com/').check();
 await page.getByLabel('Client IPs or networks (optional)').fill('192.0.2.20');
 await page.getByLabel('Path',{exact:true}).fill('/api/editor');
 await page.getByLabel('HTTP methods (optional)').fill('POST, PUT');
 await page.getByLabel('CRS rule IDs to skip').fill('941100, 941160');
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.getByRole('dialog')).not.toBeVisible();
 const card=page.getByRole('article',{name:'Editor markup',exact:true});
 await expect(card).toContainText('192.0.2.20/32');
 await page.reload();await expect(card).toBeVisible();
 await page.getByLabel('Search exceptions').fill('not-present');
 await expect(page.getByText('No matching exceptions',{exact:true})).toBeVisible();
 await page.getByLabel('Search exceptions').fill('941160');await expect(card).toBeVisible();
 await page.getByLabel('Scope',{exact:true}).selectOption('global');await expect(card).not.toBeVisible();
 await page.getByLabel('Scope',{exact:true}).selectOption('clients');await expect(card).toBeVisible();
 await card.getByRole('button',{name:'Disable',exact:true}).click();await expect(card.getByText('Disabled',{exact:true})).toBeVisible();
 await page.getByLabel('Status',{exact:true}).selectOption('enabled');await expect(card).not.toBeVisible();
 await page.getByLabel('Status',{exact:true}).selectOption('');
 await card.getByRole('button',{name:'Edit',exact:true}).click();
 await page.getByLabel('Applies to',{exact:true}).selectOption('global');
 await page.getByLabel('Client IPs or networks (optional)').fill('');
 await page.getByLabel('Enable exception',{exact:true}).check();
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.getByRole('dialog')).not.toBeVisible();
 await page.getByLabel('Scope',{exact:true}).selectOption('global');await expect(card).toContainText('All hosts');
 await page.evaluate(()=>{scrollTo(0,0);document.querySelector('#toast').hidden=true;});
 await page.screenshot({path:testInfo.outputPath('exceptions-desktop.png'),fullPage:true});
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBeTruthy();
 await page.evaluate(()=>scrollTo(0,0));
 await page.screenshot({path:testInfo.outputPath('exceptions-mobile.png'),fullPage:true});
 await card.getByRole('button',{name:'Delete',exact:true}).click();
 await page.getByRole('dialog').getByRole('button',{name:'Delete',exact:true}).click();
 await expect(card).not.toBeVisible();
});

test('event creates an editable disabled draft with only detection rules',async({page})=>{
 await page.route('**/api/events',route=>route.fulfill({json:[{id:'false-positive',time:new Date().toISOString(),host:'editor.example.com',route:'Editor application',routeId:'exception-host',path:'/api/editor',method:'POST',client:'192.0.2.20',action:'blocked',status:403,reason:'OWASP CRS',ruleIds:[941100,949110],duration:1}]}));
 await page.goto('/#events');await page.reload();
 await page.locator('[data-event="false-positive"]').click();
 await page.getByRole('button',{name:'Create exception from request'}).click();
 await expect(page.getByRole('heading',{name:'Exceptions',exact:true})).toBeVisible();
 await expect(page.getByLabel('CRS rule IDs to skip')).toHaveValue('941100');
 await expect(page.getByLabel('Enable exception',{exact:true})).not.toBeChecked();
 await expect(page.getByLabel('Editor application · editor.example.com/')).toBeChecked();
 await expect(page.getByLabel('Path',{exact:true})).toHaveValue('/api/editor');
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.getByRole('dialog')).not.toBeVisible();
 await expect(page.getByRole('article')).toContainText('Disabled');
});

test('validation errors keep the draft open and legacy exclusions are central',async({page})=>{
 await page.getByRole('button',{name:'Add exception',exact:true}).click();
 await page.getByLabel('Exception name',{exact:true}).fill('Invalid');
 await page.getByLabel('Reason',{exact:true}).fill('Test');
 await page.getByLabel('CRS rule IDs to skip').fill('941100');
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.locator('#dialog-error')).toHaveText('Select at least one host.');
 await page.getByLabel('Applies to',{exact:true}).selectOption('global');
 await page.getByLabel('CRS rule IDs to skip').fill('949110');
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.locator('#dialog-error')).toContainText('anomaly evaluation');
 await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.getByRole('link',{name:'Proxy Hosts',exact:true}).click();
 await page.getByRole('button',{name:'Edit',exact:true}).click();
 await expect(page.getByLabel('Excluded CRS rule IDs',{exact:false})).toHaveCount(0);
 await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await page.evaluate(async()=>{
  const s=await (await fetch('/api/session')).json(),c=await (await fetch('/api/config')).json();c.routes[0].excludedRuleIds=[920350];
  const r=await fetch('/api/config',{method:'PUT',headers:{'Content-Type':'application/json','X-CSRF-Token':s.csrf,'If-Match':String(c.revision)},body:JSON.stringify(c)});if(!r.ok)throw Error(await r.text());
 });
 await page.goto('/#exceptions');await page.reload();
 await page.getByRole('button',{name:'Edit existing exclusion',exact:true}).click();
 await expect(page.getByLabel('Excluded CRS rule IDs',{exact:true})).toHaveValue('920350');
 await page.getByLabel('Excluded CRS rule IDs',{exact:true}).fill('');
 await page.getByRole('dialog').getByRole('button',{name:'Save',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Existing host exclusions',exact:true})).toHaveCount(0);
});

test('failed saves retain the exception draft',async({page})=>{
 await page.getByRole('button',{name:'Add exception',exact:true}).click();
 await page.getByLabel('Exception name',{exact:true}).fill('Keep draft');
 await page.getByLabel('Reason',{exact:true}).fill('Reviewed');
 await page.getByLabel('Applies to',{exact:true}).selectOption('global');
 await page.getByLabel('CRS rule IDs to skip').fill('941100');
 await page.route('**/api/config',route=>route.request().method()==='PUT'?route.fulfill({status:409,json:{error:'configuration changed meanwhile; please reload'}}):route.continue());
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.locator('#dialog-error')).toContainText('configuration changed');
 await expect(page.getByLabel('Exception name',{exact:true})).toHaveValue('Keep draft');
 await expect(page.getByRole('button',{name:'Save exception',exact:true})).toBeEnabled();
});

test('URL source conditions save, reload, switch header and can be removed',async({page})=>{
 await page.getByRole('button',{name:'Add exception',exact:true}).click();
 await page.getByLabel('Exception name',{exact:true}).fill('Portal source');
 await page.getByLabel('Reason',{exact:true}).fill('Reviewed portal integration');
 await page.getByLabel('Applies to',{exact:true}).selectOption('global');
 await page.getByLabel('CRS rule IDs to skip').fill('941100');
 await expect(page.getByLabel('Source URLs',{exact:true})).not.toBeVisible();
 await page.getByLabel('URL source header',{exact:true}).selectOption('Origin');
 await expect(page.getByLabel('Source URLs',{exact:true})).toHaveAttribute('required','');
 await expect(page.getByLabel('Source URL matching',{exact:true})).toBeDisabled();
 await page.getByLabel('Source URLs',{exact:true}).fill('https://portal.example.com\nhttps://other.example.com');
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.getByRole('dialog')).not.toBeVisible();
 await page.reload();
 const card=page.getByRole('article',{name:'Portal source',exact:true});
 await expect(card).toContainText('Origin · Exact: https://portal.example.com, https://other.example.com');
 await page.getByLabel('Search exceptions').fill('portal.example.com');await expect(card).toBeVisible();
 await card.getByRole('button',{name:'Edit',exact:true}).click();
 await expect(page.getByLabel('Source URLs',{exact:true})).toHaveValue('https://portal.example.com\nhttps://other.example.com');
 await page.getByLabel('URL source header',{exact:true}).selectOption('Referer');
 await expect(page.getByLabel('Source URL matching',{exact:true})).toBeEnabled();
 await page.getByLabel('Source URL matching',{exact:true}).selectOption('prefix');
 await page.getByLabel('Source URLs',{exact:true}).fill('https://portal.example.com/editor');
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.getByRole('dialog')).not.toBeVisible();
 await expect(card).toContainText('Referer · Prefix: https://portal.example.com/editor');
 await card.getByRole('button',{name:'Edit',exact:true}).click();
 await page.getByLabel('URL source header',{exact:true}).selectOption('');
 await page.getByRole('button',{name:'Save exception',exact:true}).click();
 await expect(page.getByRole('dialog')).not.toBeVisible();
 await page.getByLabel('Search exceptions').fill('');
 await expect(card).toContainText('Any source');
});
