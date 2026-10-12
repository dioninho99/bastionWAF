const { test, expect } = require('@playwright/test');
test.beforeEach(async ({page})=>{page.on('pageerror',error=>{throw error;});});
async function login(page, username='', password='browser-test-admin-password') {
 await page.goto('/');
 await page.getByLabel('Username', {exact:false}).fill(username);
 await page.getByLabel('Password', {exact:true}).fill(password);
 await page.getByRole('button',{name:'Sign in to Bastion'}).click();
 await expect(page.locator('#shell')).toBeVisible();
}
test('create local user, sign in with 12 characters, change role and password', async ({page,browser}) => {
 await login(page);
 await page.getByRole('link',{name:'Users',exact:true}).click();
 await page.locator('#local-user-form').getByLabel('Username',{exact:true}).fill('browser-user');
 await page.locator('#local-user-form').getByLabel('Password',{exact:true}).fill('LocalPass123!');
 await page.getByRole('button',{name:'Create user',exact:true}).click();
 const row=page.getByRole('row').filter({hasText:'local:browser-user'});
 await expect(row).toBeVisible();
 const context=await browser.newContext({baseURL:'http://127.0.0.1:19091'});const local=await context.newPage();
 await login(local,'browser-user','LocalPass123!');
 await row.getByRole('combobox').selectOption('admin');
 await expect(page.locator('#toast')).toHaveText('Access level saved.');
 await row.getByRole('button',{name:'Change password'}).click();
 await expect(page.getByLabel('New password')).toHaveAttribute('type','password');
 await page.getByLabel('New password').fill('ChangedPass1!');
 await page.getByRole('dialog').getByRole('button',{name:'Change password',exact:true}).click();
 await expect(page.getByRole('dialog')).not.toBeVisible();
 await local.reload();await expect(local.locator('#login')).toBeVisible();
 await login(local,'browser-user','ChangedPass1!');
 await context.close();
});
test('TLS modes preserve saved values and show restart pending',async ({page})=>{
 await login(page);await page.getByRole('link',{name:'Certificates',exact:true}).click();
 await expect(page.locator('.restart-note')).toContainText('Active configuration');
 await page.getByLabel('TLS mode',{exact:true}).selectOption('dns01');
 await expect(page.getByLabel('Cloudflare API token')).toBeVisible();
 await page.getByLabel('TLS mode',{exact:true}).selectOption('http01');
 await expect(page.getByLabel('Cloudflare API token')).not.toBeVisible();
 await page.getByLabel('ACME email').fill('browser@example.test');
 await page.getByRole('button',{name:'Save TLS settings'}).click();
 await expect(page.locator('.restart-note')).toContainText('Saved · restart pending');
 await page.reload();await expect(page.getByLabel('ACME email')).toHaveValue('browser@example.test');
 await expect(page.locator('.restart-note')).toContainText('Saved · restart pending');
});
test('OIDC no-op save stays active; changed settings and revert update status',async ({page})=>{
 await login(page);await page.getByRole('link',{name:'OIDC',exact:true}).click();
 await expect(page.locator('.restart-note')).toContainText('Active configuration');
 await page.getByRole('button',{name:'Save OIDC settings'}).click();
 await expect(page.locator('#toast')).toBeVisible();
 await expect(page.locator('.restart-note')).toContainText('Active configuration');
 await page.getByLabel('Role claim').fill('groups');
 await page.getByRole('button',{name:'Save OIDC settings'}).click();
 await expect(page.locator('.restart-note')).toContainText('restart pending');
 await page.getByLabel('Role claim').fill('role');
 await page.getByRole('button',{name:'Save OIDC settings'}).click();
 await expect(page.locator('.restart-note')).toContainText('Active configuration');
});

test('management forms remain usable on a narrow viewport',async ({page})=>{
 await page.setViewportSize({width:390,height:844});
 await login(page);
 for(const name of ['Users','OIDC','Certificates']) {
  await page.getByRole('link',{name,exact:true}).click();
  await expect(page.locator('#main h1')).toHaveText(name,{ignoreCase:true});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 }
 await expect(page.locator('#logout')).toBeVisible();
});
test('IP exceptions and trusted proxies survive save and reload',async ({page})=>{
 await login(page);
 await page.getByRole('link',{name:'WAF protection',exact:true}).click();
 await page.getByLabel('IP exceptions to country rules',{exact:true}).fill('192.0.2.20');
 await page.getByLabel('Trusted proxy IPs or networks',{exact:true}).fill('10.0.0.5');
 await page.getByRole('button',{name:'Save access control',exact:true}).click();
 await expect(page.locator('#toast')).toBeVisible();
 await page.reload();
 await expect(page.getByLabel('IP exceptions to country rules',{exact:true})).toHaveValue('192.0.2.20/32');
 await expect(page.getByLabel('Trusted proxy IPs or networks',{exact:true})).toHaveValue('10.0.0.5/32');
 await page.getByRole('link',{name:/^Proxy Hosts/}).click();
 await page.getByRole('button',{name:'Add proxy host',exact:true}).click();
 const dialog=page.getByRole('dialog');
 await dialog.getByLabel('Application name').fill('Access test');
 await dialog.getByLabel('Domain',{exact:true}).fill('access.example.com');
 await dialog.getByLabel('Backend addresses',{exact:false}).fill('http://93.184.216.34');
 await dialog.getByLabel('IP whitelist',{exact:true}).fill('2001:db8::1');
 await dialog.getByLabel('IP exceptions to country rules',{exact:true}).fill('2001:db8::1');
 await dialog.getByRole('button',{name:'Save',exact:true}).click();
 await expect(dialog).not.toBeVisible();
 await page.getByRole('row').filter({hasText:'Access test'}).getByRole('button',{name:'Edit',exact:true}).click();
 await expect(dialog.getByLabel('IP exceptions to country rules',{exact:true})).toHaveValue('2001:db8::1/128');
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBeTruthy();
});

test('certificate dashboard reports validity and renewal without resetting setup',async({page})=>{
 const now=Date.now();let running=false;let renews=0;
 await page.route('**/api/tls',route=>route.fulfill({json:{mode:'dns01',runtimeKnown:true,restartRequired:false,email:'admin@example.test',domains:['example.test'],dnsTokenConfigured:true}}));
 await page.route('**/api/tls/status',route=>route.fulfill({json:{mode:'dns01',enabled:true,canRenew:!running,failures:{},renewal:{running,lastAttempt:new Date(now-86400000).toISOString(),lastSuccess:new Date(now-86400000).toISOString(),nextAttempt:new Date(now+3600000).toISOString()},certificates:[{domain:'DNS-01 certificate',dnsNames:['example.test','*.example.test'],issuer:'CN=Test CA',notBefore:new Date(now-86400000).toISOString(),notAfter:new Date(now+60*86400000).toISOString(),fingerprint:'a'.repeat(64),state:'valid'}]}}));
 await page.route('**/api/tls/renew',route=>{renews++;running=true;return route.fulfill({status:202,json:{status:'queued'}});});
 await login(page);await page.getByRole('link',{name:'Certificates',exact:true}).click();

 await expect(page.getByRole('heading',{name:'Certificate available'})).toBeVisible();
 await expect(page.locator('.certificate-card')).toContainText('60 days');
 await page.getByLabel('TLS mode',{exact:true}).selectOption('http01');
 await page.getByLabel('ACME email').fill('unsaved@example.test');
 page.on('dialog',dialog=>dialog.accept());
 await page.getByRole('button',{name:'Renew certificate now'}).click();
 await expect(page.getByRole('button',{name:'Request in progress…'})).toBeDisabled();
 expect(renews).toBe(1);
 await expect(page.getByLabel('ACME email')).toHaveValue('unsaved@example.test');
 await page.setViewportSize({width:390,height:844});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.screenshot({path:test.info().outputPath('certificate-dashboard.png'),fullPage:true});
});
