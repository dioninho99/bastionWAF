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
