import assert from 'node:assert/strict';
import { test } from 'node:test';
import { connectDashboard } from './useDashboardSocket.js';

test('reconnect requests a new snapshot and ignores frames from the previous connection', () => {
  const sockets = [];
  const events = [];
  let retry;
  class FakeSocket {
    constructor() {
      sockets.push(this);
    }
    close() {
      this.onclose();
    }
  }
  const dispose = connectDashboard('ws://dashboard.test', {
    open: () => events.push('snapshot'),
    message: (event) => events.push(event.version),
    close: () => events.push('disconnected'),
  }, {
    WebSocket: FakeSocket,
    setTimeout: (callback) => { retry = callback; },
    clearTimeout: () => { retry = null; },
  });

  sockets[0].onopen();
  sockets[0].close();
  retry();
  sockets[1].onopen();
  sockets[0].onmessage({ data: '{"version":"old"}' });
  sockets[1].onmessage({ data: '{"version":"new"}' });
  dispose();
  assert.deepEqual(events, ['snapshot', 'disconnected', 'snapshot', 'new']);
  assert.equal(retry, null);
});
