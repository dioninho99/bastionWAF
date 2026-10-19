'use strict';

const exceptionFilters = {query:'',scope:'',status:''};
const tunableRuleID = id => id >= 920000 && id < 949000 || id >= 950000 && id < 959000;
function exceptionScope(e) {
 return e.scope==='global' ? 'All hosts' : e.routeIds.map(id=>{const r=state.config.routes.find(r=>r.id===id);return r?`${r.name} (${r.host}${r.path})`:'Removed host';}).join(', ');
}
function exceptions() {
 const entries=state.config.exceptions||[];
 return head('Exceptions','Fine-tune protection in one place. Limit an exception to selected hosts, client devices, endpoints, and methods.',`<button class="primary" data-add-exception>${icon('plus')} Add exception</button>`)+`
 <div class="summary-tiles exception-summary"><div><span>Total exceptions</span><strong>${entries.length}</strong></div><div><span>Enabled</span><strong>${entries.filter(e=>e.enabled).length}</strong></div><div><span>All hosts</span><strong>${entries.filter(e=>e.scope==='global').length}</strong></div></div>
 <p class="info">Only the selected CRS detection rules are skipped. IP and country restrictions, login, custom rules, and traffic limits still apply. All conditions in an exception must match.</p>
 <section class="panel exception-panel"><div class="exception-filters"><div class="field"><label for="exception-search">Search exceptions</label><input id="exception-search" type="search" placeholder="Name, host, IP, path, rule ID…" value="${esc(exceptionFilters.query)}"></div><div class="field"><label for="exception-scope-filter">Scope</label><select id="exception-scope-filter"><option value="">All scopes</option><option value="global" ${exceptionFilters.scope==='global'?'selected':''}>All hosts</option><option value="hosts" ${exceptionFilters.scope==='hosts'?'selected':''}>Selected hosts</option><option value="clients" ${exceptionFilters.scope==='clients'?'selected':''}>Specific clients</option></select></div><div class="field"><label for="exception-status-filter">Status</label><select id="exception-status-filter"><option value="">All statuses</option><option value="enabled" ${exceptionFilters.status==='enabled'?'selected':''}>Enabled</option><option value="disabled" ${exceptionFilters.status==='disabled'?'selected':''}>Disabled</option></select></div></div><div id="exception-list">${exceptionList()}</div></section>${legacyExceptions()}`;
}
function exceptionList() {
 const entries=state.config.exceptions||[], q=exceptionFilters.query.trim().toLowerCase();
 const filtered=entries.filter(e=>(!q||[e.name,e.reason,exceptionScope(e),...(e.clientCIDRs||[]),...(e.sourceURLs||[]),e.sourceHeader||'',e.path,...e.ruleIds,...e.methods].join(' ').toLowerCase().includes(q))&&(!exceptionFilters.scope||(exceptionFilters.scope==='clients'?e.clientCIDRs?.length:e.scope===exceptionFilters.scope))&&(!exceptionFilters.status||e.enabled===(exceptionFilters.status==='enabled')));
 if(!filtered.length)return empty(entries.length?'No matching exceptions':'No exceptions yet',entries.length?'Change your search or filters.':'Create a targeted exception for a confirmed false positive.');
 return `<p class="field-help" role="status">${filtered.length} of ${entries.length} exceptions</p><div class="exception-cards">${filtered.map(e=>`<article class="exception-card" aria-label="${esc(e.name)}"><div class="section-heading-row"><h3>${esc(e.name)}</h3><span class="badge ${e.enabled?'':'gray'}">${e.enabled?'Enabled':'Disabled'}</span></div><p>${esc(e.reason)}</p><dl class="exception-facts"><div><dt>Hosts</dt><dd>${esc(exceptionScope(e))}</dd></div><div><dt>Clients / devices</dt><dd>${esc(e.clientCIDRs?.join(', ')||'All clients')}</dd></div><div><dt>URL source</dt><dd>${esc(e.sourceHeader?`${e.sourceHeader} · ${e.sourceMatch==='prefix'?'Prefix':'Exact'}: ${(e.sourceURLs||[]).join(', ')}`:'Any source')}</dd></div><div><dt>Endpoint</dt><dd>${esc(e.match==='prefix'&&e.path==='/'?'All paths':`${e.match==='exact'?'Exact':'Prefix'}: ${e.path}`)}</dd></div><div><dt>Methods</dt><dd>${esc(e.methods?.join(', ')||'All methods')}</dd></div><div><dt>Skipped rules</dt><dd>${esc(e.ruleIds.join(', '))}</dd></div></dl><div class="row-actions"><button class="secondary" data-edit-exception="${esc(e.id)}">Edit</button><button class="secondary" data-toggle-exception="${esc(e.id)}">${e.enabled?'Disable':'Enable'}</button><button class="danger" data-delete-exception="${esc(e.id)}">Delete</button></div></article>`).join('')}</div>`;
}
function legacyExceptions() {
 const routes=state.config.routes.filter(r=>r.excludedRuleIds?.length);
 if(!routes.length)return '';
 return `<section class="panel exception-panel"><h2>Existing host exclusions</h2><p>These older exclusions cover the entire host route. They remain active and are now managed here. Replace them with a targeted exception where possible.</p>${routes.map(r=>`<div class="exception-card"><h3>${esc(r.name)} · ${esc(r.host)}</h3><p>Route ${esc(r.path)} · Rules ${esc(r.excludedRuleIds.join(', '))}</p><button class="secondary" data-legacy-exception="${esc(r.id)}">Edit existing exclusion</button></div>`).join('')}</section>`;
}
function exceptionEditor(id, draft) {
 const e=(state.config.exceptions||[]).find(x=>x.id===id)||{id:crypto.randomUUID(),name:'',reason:'',enabled:true,scope:'hosts',routeIds:[],clientCIDRs:[],path:'/',match:'exact',methods:[],ruleIds:[],...draft};
 openDialog(id?'Edit exception':'Create exception',`
 <div class="field"><label for="exception-name">Exception name</label><input id="exception-name" name="name" required maxlength="100" value="${esc(e.name)}" placeholder="Rich text editor false positive"></div>
 <div class="field"><label for="exception-reason">Reason</label><textarea id="exception-reason" name="reason" required maxlength="500" rows="2" placeholder="Why is this traffic legitimate?">${esc(e.reason)}</textarea></div>
 <div class="field"><label for="exception-scope">Applies to</label><select id="exception-scope" name="scope"><option value="hosts" ${e.scope==='hosts'?'selected':''}>Selected hosts</option><option value="global" ${e.scope==='global'?'selected':''}>All hosts (including future hosts)</option></select></div>
 <fieldset id="exception-hosts" ${e.scope==='global'?'hidden':''}><legend>Select hosts</legend>${state.config.routes.length?state.config.routes.map(r=>`<label class="check"><input type="checkbox" name="routeIds" value="${esc(r.id)}" ${(e.routeIds||[]).includes(r.id)?'checked':''}> ${esc(r.name)} · ${esc(r.host)}${esc(r.path)}</label>`).join(''):'<p>Add a proxy host first, or choose all hosts.</p>'}</fieldset>
 <div class="field"><label for="exception-clients">Client IPs or networks (optional)</label><textarea id="exception-clients" name="clientCIDRs" rows="2" placeholder="192.0.2.20 or 192.0.2.0/24">${esc((e.clientCIDRs||[]).join('\n'))}</textarea><p class="field-help">Empty means all clients. Devices are identified by IP address; clients behind the same NAT share an IP. Trusted proxy settings determine the client address.</p></div>
 <div class="field"><label for="exception-source-header">URL source header</label><select id="exception-source-header" name="sourceHeader"><option value="">Any source</option><option value="Origin" ${e.sourceHeader==='Origin'?'selected':''}>Origin · originating website</option><option value="Referer" ${e.sourceHeader==='Referer'?'selected':''}>Referer · referring page</option></select></div>
 <div id="exception-source-fields"><div class="field"><label for="exception-source-urls">Source URLs</label><textarea id="exception-source-urls" name="sourceURLs" rows="3" placeholder="https://portal.example.com">${esc((e.sourceURLs||[]).join('\n'))}</textarea><p class="field-help">One URL per line. Origin: scheme and host only. Referer: a full page URL or a path prefix. No wildcards, query strings, or fragments. Missing or different headers do not match; there is no fallback between headers.</p></div><div class="field"><label for="exception-source-match">Source URL matching</label><select id="exception-source-match" name="sourceMatch"><option value="exact">Exact URL</option><option value="prefix" ${e.sourceMatch==='prefix'?'selected':''}>URL and child paths (Referer only)</option></select></div><p class="info warning">Origin and Referer can be missing or forged. Use this as an additional condition, not as authentication. Browsers may send only the website origin in Referer.</p></div>
 <div class="form-grid"><div class="field"><label for="exception-match">Path matching</label><select id="exception-match" name="match"><option value="exact" ${e.match==='exact'?'selected':''}>Exact path</option><option value="prefix" ${e.match==='prefix'?'selected':''}>Path and child paths</option></select></div><div class="field"><label for="exception-path">Path</label><input id="exception-path" name="path" required maxlength="500" value="${esc(e.path)}" placeholder="/api/editor"></div></div><p class="field-help">Use the decoded path without query parameters. A prefix of / covers all paths. /api matches /api and /api/…, but not /api-other.</p>
 <div class="field"><label for="exception-methods">HTTP methods (optional)</label><input id="exception-methods" name="methods" value="${esc((e.methods||[]).join(', '))}" placeholder="POST, PUT"><p class="field-help">Empty means all methods.</p></div>
 <div class="field"><label for="exception-rules">CRS rule IDs to skip</label><input id="exception-rules" name="ruleIds" required value="${esc(e.ruleIds.join(', '))}" placeholder="941100, 941160"><p class="field-help">Use detection rule IDs from Events. Anomaly evaluation rules such as 949110 cannot be excluded.</p></div>
 <label class="check"><input type="checkbox" name="enabled" ${e.enabled?'checked':''}> Enable exception</label><p class="info" id="exception-preview"></p>`,async f=>{
  const next=clone(), scope=f.get('scope');
  const updated={id:e.id,name:f.get('name').trim(),reason:f.get('reason').trim(),enabled:f.has('enabled'),scope,routeIds:scope==='hosts'?f.getAll('routeIds'):[],clientCIDRs:lines(f.get('clientCIDRs')),sourceHeader:f.get('sourceHeader'),sourceMatch:f.get('sourceHeader')?(f.get('sourceHeader')==='Origin'?'exact':f.get('sourceMatch')):'',sourceURLs:f.get('sourceHeader')?String(f.get('sourceURLs')).split(/\r?\n/).map(x=>x.trim()).filter(Boolean):[],path:f.get('path').trim(),match:f.get('match'),methods:lines(f.get('methods')).map(x=>x.toUpperCase()),ruleIds:lines(f.get('ruleIds')).map(Number)};
  if(scope==='hosts'&&!updated.routeIds.length)throw new Error('Select at least one host.');
  if(!updated.ruleIds.length||updated.ruleIds.some(n=>!Number.isInteger(n)||!tunableRuleID(n)))throw new Error('Select valid CRS detection rule IDs; anomaly evaluation cannot be excluded.');
  next.exceptions=next.exceptions||[];const idx=next.exceptions.findIndex(x=>x.id===e.id);if(idx<0)next.exceptions.push(updated);else next.exceptions[idx]=updated;
  await saveConfig(next);
 },'Save exception');
 const preview=()=>{const source=$('#exception-source-header').value;$('#exception-source-fields').hidden=!source;$('#exception-source-urls').required=!!source;$('#exception-source-match').disabled=source==='Origin';if(source==='Origin')$('#exception-source-match').value='exact';const f=new FormData($('#editor-form'));$('#exception-hosts').hidden=f.get('scope')==='global';$('#exception-preview').textContent=`${f.has('enabled')?'Enabled':'Disabled'} · ${f.get('scope')==='global'?'All current and future hosts':`${f.getAll('routeIds').length} selected hosts`} · ${lines(f.get('clientCIDRs')).length?'Selected client IPs/networks':'All clients'} · ${f.get('match')==='exact'?'Exact':'Prefix'} ${f.get('path')} · ${f.get('methods').trim()||'All methods'} · ${source?source+': '+(f.get('sourceURLs').trim()||'Enter source URL'):'Any URL source'}`;};
 $('#dialog-fields').oninput=preview;preview();
}
function exceptionFromEvent(e) {
 // Historical events lack a stable route ID. Only preselect an unambiguous
 // route; the administrator must select a host when attribution is uncertain.
 const candidates=state.config.routes.filter(r=>r.host===e.host&&r.name===e.route);
 const route=state.config.routes.find(r=>r.id===e.routeId)||(!e.routeId&&candidates.length===1?candidates[0]:null);
 let path=e.path;try{path=decodeURIComponent(path);}catch{}
 $('#editor').close();location.hash='exceptions';
 exceptionEditor(null,{name:`False positive: ${e.method} ${path}`.slice(0,100),reason:`Review of request ${e.id}`,routeIds:route?[route.id]:[],path,methods:[e.method],ruleIds:e.ruleIds.filter(tunableRuleID),enabled:false});
}
document.addEventListener('input',event=>{
 if(event.target.id==='exception-search'){exceptionFilters.query=event.target.value;$('#exception-list').innerHTML=exceptionList();}
});
document.addEventListener('change',event=>{
 const key={'exception-scope-filter':'scope','exception-status-filter':'status'}[event.target.id];if(key){exceptionFilters[key]=event.target.value;$('#exception-list').innerHTML=exceptionList();}
});
document.addEventListener('click',async event=>{
 const el=event.target.closest('button');if(!el)return;
 try {
  if(el.hasAttribute('data-add-exception'))exceptionEditor();
  if(el.dataset.editException)exceptionEditor(el.dataset.editException);
  if(el.dataset.exceptionEvent){const e=state.events.find(x=>x.id===el.dataset.exceptionEvent);if(e)exceptionFromEvent(e);}
  if(el.dataset.toggleException){el.disabled=true;const next=clone(),e=next.exceptions.find(x=>x.id===el.dataset.toggleException);e.enabled=!e.enabled;await saveConfig(next);render();}
  if(el.dataset.deleteException){const e=state.config.exceptions.find(x=>x.id===el.dataset.deleteException);openDialog('Delete exception?',`<p>Remove “${esc(e.name)}”? Its selected rules will be inspected again unless another exception applies.</p>`,async()=>{const next=clone();next.exceptions=next.exceptions.filter(x=>x.id!==e.id);await saveConfig(next);},'Delete');}
  if(el.dataset.legacyException){const r=state.config.routes.find(x=>x.id===el.dataset.legacyException);openDialog('Edit existing host exclusion',`<p>${esc(r.name)} · ${esc(r.host)}${esc(r.path)}</p><div class="field"><label for="legacy-rules">Excluded CRS rule IDs</label><input id="legacy-rules" name="rules" value="${esc(r.excludedRuleIds.join(', '))}"><p class="field-help">Clear this field to remove the existing exclusion.</p></div>`,async f=>{const next=clone();next.routes.find(x=>x.id===r.id).excludedRuleIds=lines(f.get('rules')).map(Number);await saveConfig(next);});}
 }catch(err){toast(err.message,true);el.disabled=false;}
});
