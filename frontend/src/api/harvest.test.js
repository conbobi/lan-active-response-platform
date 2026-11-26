import assert from 'node:assert/strict';
import { test } from 'node:test';
import api from './api.js';
import { clearAuthSession, saveSession } from './operatorSession.js';
import { harvestRule } from './rules.js';

for (const retryStatus of [200, 401]) {
  test(`harvest refreshes once when the retry returns ${retryStatus}`, async (t) => {
    const calls = [];
    const payload = { cti_text: 'Synthetic CTI report' };
    const adapter = api.defaults.adapter;
    const originalWindow = globalThis.window;
    globalThis.window = new EventTarget();
    t.after(() => {
      if (originalWindow === undefined) delete globalThis.window;
      else globalThis.window = originalWindow;
      api.defaults.adapter = adapter;
      clearAuthSession();
    });
    saveSession('expired');
    api.defaults.adapter = async (config) => {
      calls.push(config.url);
      assert.ok(calls.length <= 3, "harvest retried more than once");
      if (config.url === '/auth/refresh') {
        assert.equal(config.withCredentials, true);
        assert.equal(config.headers.get('X-LARP-CSRF'), '1');
        return { data: { access_token: 'renewed' }, status: 200, config };
      }
      assert.equal(config.url, '/rules/harvest');
      assert.equal(config.method, 'post');
      assert.deepEqual(JSON.parse(config.data), payload);
      const first = calls.length === 1;
      assert.equal(config.headers.Authorization, first ? 'Bearer expired' : 'Bearer renewed');
      if (first || retryStatus === 401) {
        throw Object.assign(new Error('Unauthorized'), { config, response: { status: 401 } });
      }
      return { data: { rule_id: 'candidate' }, status: 200, config };
    };

    if (retryStatus === 200) {
      assert.deepEqual(await harvestRule(payload), { rule_id: 'candidate' });
    } else {
      await assert.rejects(harvestRule(payload), { status: 401 });
    }
    assert.deepEqual(calls, ['/rules/harvest', '/auth/refresh', '/rules/harvest']);
  });
}
