import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';

test('server responds to /health', async (t) => {
  const PORT = 4001;
  const env = { ...process.env, PORT: String(PORT) };
  const server = spawn(process.execPath, ['dist/index.js'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
  });

  let started = false;
  server.stdout.on('data', (d) => {
    const s = String(d);
    if (s.includes('listening on')) started = true;
  });

  // wait for server to start (or 2s)
  for (let i = 0; i < 20 && !started; i++) {
    await new Promise((r) => setTimeout(r, 100));
  }

  const res = await fetch(`http://127.0.0.1:${PORT}/health`);
  const body = await res.text();
  assert.strictEqual(body, 'ok');

  server.kill();
});
