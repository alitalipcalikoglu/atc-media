import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { MediaApi } from '../src/http/media-api.js';
import { VirusScanner } from '../src/storage/virus-scanner.js';
import { API_KEY, OTHER_KEY, silentLog, testConfig, testImage, testMediaService } from './helpers.js';

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

/** Minimal clamd: answers PING and INSTREAM, flags any stream that contains the EICAR string. */
class FakeClamd {
  constructor() {
    this.down = false;
    this.server = createServer((socket) => {
      /** @type {Buffer} */ let buf = Buffer.alloc(0);
      socket.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        if (this.down) { socket.destroy(); return; }
        if (buf.toString('latin1').startsWith('zPING\0')) { socket.end('PONG\0'); return; }
        const head = 'zINSTREAM\0';
        if (!buf.toString('latin1').startsWith(head)) return;
        let off = head.length; const parts = [];
        while (off + 4 <= buf.length) {
          const n = buf.readUInt32BE(off);
          if (n === 0) {
            const body = Buffer.concat(parts).toString('latin1');
            socket.end(body.includes('EICAR-STANDARD') ? 'stream: Eicar-Test-Signature FOUND\0' : 'stream: OK\0');
            return;
          }
          if (off + 4 + n > buf.length) return;
          parts.push(buf.subarray(off + 4, off + 4 + n)); off += 4 + n;
        }
      });
    });
  }
  async listen() { await new Promise((r) => this.server.listen(0, '127.0.0.1', () => r(null))); return /** @type {import('node:net').AddressInfo} */ (this.server.address()).port; }
}

const clamd = new FakeClamd();
/** @type {Awaited<ReturnType<typeof testMediaService>>} */ let t;
/** @type {import('fastify').FastifyInstance} */ let app;
const admin = { authorization: `Bearer ${API_KEY}` };
const user = { authorization: `Bearer ${OTHER_KEY}` };

before(async () => {
  const port = await clamd.listen();
  const env = { CLAMD_HOST: '127.0.0.1', CLAMD_PORT: String(port), CLAMD_TIMEOUT_MS: '2000', ADMIN_KEYS: 'test', ALLOWED_TYPES: 'image/png,text/csv' };
  const cfg = testConfig(env);
  t = await testMediaService(env, { scanner: new VirusScanner(/** @type {any} */ (cfg.clamd)) });
  app = await new MediaApi({ config: t.config, service: t.service, db: t.db, files: t.files, logger: silentLog, version: '0.0.0' }).build();
  await app.ready();
});
after(async () => { await app?.close(); t?.cleanup(); clamd.server.close(); });

test('config: ADMIN_KEYS must name configured keys; clamd settings parsed', () => {
  assert.throws(() => testConfig({ ADMIN_KEYS: 'ghost' }), /unknown key "ghost"/);
  const c = testConfig({ CLAMD_HOST: 'clamd', SCAN_FAIL_OPEN: 'true' });
  assert.deepEqual(c.clamd, { host: 'clamd', port: 3310, timeoutMs: 30_000 });
  assert.equal(c.scanFailOpen, true);
  assert.equal(testConfig().clamd, null);
});

test('clean uploads pass the scan; /ready pings clamd', async () => {
  const res = await app.inject({ method: 'PUT', url: '/v1/files?name=a.csv', headers: { ...user, 'content-type': 'text/csv' }, payload: 'hello' });
  assert.equal(res.statusCode, 201, res.body);
  assert.equal(res.json().file.owner, 'other');
  assert.equal((await app.inject('/ready')).statusCode, 200);
  assert.ok((await app.inject({ url: '/v1/info' })).json().capabilities.includes('virus-scan'));
});

test('infected upload: 422 INFECTED, quarantined, admin lists and deletes it', async () => {
  const res = await app.inject({ method: 'PUT', url: '/v1/files?name=bad.csv', headers: { ...user, 'content-type': 'text/csv' }, payload: EICAR });
  assert.equal(res.statusCode, 422, res.body);
  const err = res.json().error;
  assert.equal(err.code, 'INFECTED');
  const qid = err.details.quarantineId;
  assert.match(qid, /^q_/);
  assert.equal((await app.inject({ url: '/v1/quarantine', headers: user })).statusCode, 403);
  const list = (await app.inject({ url: '/v1/quarantine', headers: admin })).json().items;
  assert.equal(list.length, 1);
  assert.equal(list[0].owner, 'other');
  assert.equal(list[0].signature, 'Eicar-Test-Signature');
  assert.equal((await app.inject({ url: '/v1/files', headers: user })).json().items.every((/** @type {any} */ f) => f.name !== 'bad.csv'), true);
  assert.ok(existsSync(join(t.dir, 'quarantine', qid)), 'bytes kept in quarantine');
  assert.match((await app.inject({ url: '/metrics', headers: admin })).body, /media_quarantined 1/);
  assert.equal((await app.inject({ method: 'DELETE', url: `/v1/quarantine/${qid}`, headers: user })).statusCode, 403);
  assert.equal((await app.inject({ method: 'DELETE', url: `/v1/quarantine/${qid}`, headers: admin })).statusCode, 204);
  assert.ok(!existsSync(join(t.dir, 'quarantine', qid)), 'bytes removed');
  assert.equal((await app.inject({ method: 'DELETE', url: `/v1/quarantine/${qid}`, headers: admin })).statusCode, 404);
});

test('purge removes quarantine entries older than QUARANTINE_DAYS', async () => {
  const res = await app.inject({ method: 'PUT', url: '/v1/files?name=bad2.csv', headers: { ...user, 'content-type': 'text/csv' }, payload: EICAR });
  assert.equal(res.statusCode, 422);
  t.clock.now += 31 * 86_400_000;
  const r = await t.service.purge();
  assert.equal(r.quarantine, 1);
  assert.equal(t.files.quarantineCount(), 0);
  t.clock.now -= 31 * 86_400_000;
});

test('scanner down: 503 SCAN_UNAVAILABLE (fail closed), nothing stored', async () => {
  clamd.down = true;
  try {
    const res = await app.inject({ method: 'PUT', url: '/v1/files?name=c.csv', headers: { ...user, 'content-type': 'text/csv' }, payload: 'later' });
    assert.equal(res.statusCode, 503, res.body);
    assert.equal(res.json().error.code, 'SCAN_UNAVAILABLE');
    assert.equal(t.files.list({ apiKeyId: 'other', limit: 50 }).some((f) => f.name === 'c.csv'), false);
  } finally { clamd.down = false; }
});

test('admin keys see every owner, filter by owner, and manage other keys\' files', async () => {
  const png = await testImage({ format: 'png', width: 20, height: 20 });
  const up = await app.inject({ method: 'PUT', url: '/v1/files?name=p.png', headers: { ...user, 'content-type': 'image/png' }, payload: png });
  assert.equal(up.statusCode, 201, up.body);
  const id = up.json().file.id;
  const all = (await app.inject({ url: '/v1/files', headers: admin })).json().items;
  assert.ok(all.some((/** @type {any} */ f) => f.id === id));
  const own = (await app.inject({ url: '/v1/files?owner=test', headers: admin })).json().items;
  assert.ok(!own.some((/** @type {any} */ f) => f.id === id));
  // A non-admin owner filter is ignored: it always sees only its own files.
  assert.ok((await app.inject({ url: '/v1/files?owner=test', headers: user })).json().items.some((/** @type {any} */ f) => f.id === id));
  assert.equal((await app.inject({ method: 'PATCH', url: `/v1/files/${id}`, headers: admin, payload: { name: 'renamed.png' } })).json().file.name, 'renamed.png');
  assert.equal((await app.inject({ method: 'DELETE', url: `/v1/files/${id}`, headers: admin })).statusCode, 204);
  assert.equal((await app.inject({ method: 'POST', url: `/v1/files/${id}/restore`, headers: admin })).statusCode, 200);
  // The other way round stays closed.
  const mine = await app.inject({ method: 'PUT', url: '/v1/files?name=q.png', headers: { ...admin, 'content-type': 'image/png' }, payload: png });
  assert.equal((await app.inject({ url: `/v1/files/${mine.json().file.id}`, headers: user })).statusCode, 404);
});
