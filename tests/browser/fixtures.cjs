const {test:base,expect}=require('@playwright/test');

// Each test still receives a fresh browser context. Reuse only the admin
// session so a growing suite does not exhaust the real login rate limiter.
const test=base.extend({
 adminStorageState:[async({browser},use,workerInfo)=>{
  const context=await browser.newContext({baseURL:workerInfo.project.use.baseURL});
  let storageState;
  try {
   const page=await context.newPage();
   await page.goto('/');
   await page.getByLabel('Password',{exact:true}).fill('browser-test-admin-password');
   const responsePromise=page.waitForResponse(response=>response.url().endsWith('/api/login')&&response.request().method()==='POST');
   await page.getByRole('button',{name:'Sign in to Bastion'}).click();
   const response=await responsePromise;
   expect(response.status(),await response.text()).toBe(200);
   await expect(page.locator('#shell')).toBeVisible();
   storageState=await context.storageState();
  } finally { await context.close(); }
  await use(storageState);
 },{scope:'worker'}],
 storageState:async({adminStorageState},use)=>{await use(adminStorageState);},
});

module.exports={test,expect};
