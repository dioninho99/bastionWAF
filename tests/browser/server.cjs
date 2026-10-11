const { spawn, spawnSync } = require('node:child_process');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const dir = mkdtempSync(join(tmpdir(), 'bastion-browser-'));
const binary = join(dir, 'bastion');
const build = spawnSync('go', ['build', '-o', binary, './cmd/bastion'], { stdio: 'inherit' });
if (build.status !== 0) { rmSync(dir, {recursive:true,force:true}); process.exit(1); }
// Never inherit production TLS/OIDC credentials or configuration into the fixture.
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('BASTION_')));
Object.assign(env, { BASTION_ADMIN_PASSWORD: 'browser-test-admin-password', BASTION_DATA_DIR: dir, BASTION_ADMIN_ADDR:'127.0.0.1:19091', BASTION_HTTP_ADDR:'127.0.0.1:18091' });
const child = spawn(binary, [], { env, stdio:'inherit' });
for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('exit', code => { rmSync(dir,{recursive:true,force:true}); process.exit(code || 0); });
