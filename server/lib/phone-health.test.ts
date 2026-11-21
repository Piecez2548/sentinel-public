import assert from 'node:assert/strict';
import { test } from 'node:test';
import { judgePhone, mergeCheckin, parsePhone } from './phone-health.js';

const CHROME_ANDROID = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36';
const SAMSUNG_OLD = 'Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/106.0.5249.126 Mobile Safari/537.36';
const IPHONE_18 = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
const IPHONE_26 = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1';
const IPHONE_16 = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_10 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1';
const IPAD_AS_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15';
const CHROME_IOS_FROZEN = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1';
const PC = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

test('Android: the real version comes from Chrome client hints (the UA always says "Android 10; K")', () => {
  const hidden = parsePhone(CHROME_ANDROID)!;
  assert.equal(hidden.os, 'Android (version hidden)');
  assert.equal(judgePhone(hidden).status, 'unknown', 'never alarm on the frozen "10"');
  const real = parsePhone(CHROME_ANDROID, { platformVersion: '15.0.0', model: 'Pixel 8' })!;
  assert.deepEqual([real.os, real.osMajor, real.model, real.browser, real.browserVersion], ['Android 15', 15, 'Pixel 8', 'Chrome', '131.0.0.0']);
  assert.equal(judgePhone(real).status, 'ok');
  const old = parsePhone(SAMSUNG_OLD)!;
  assert.deepEqual([old.os, old.model, old.browser], ['Android 11', 'SM-A515F', 'Samsung Internet']);
  assert.equal(judgePhone(old).status, 'old');
});

test('iPhone / iPad: Safari version follows iOS; the frozen 18_6 token means "18.6 or newer"', () => {
  assert.equal(parsePhone(IPHONE_18)!.os, 'iOS 18');
  assert.equal(parsePhone(IPHONE_26)!.os, 'iOS 26', 'Safari 26 = iOS 26');
  assert.equal(judgePhone(parsePhone(IPHONE_16)!).status, 'old');
  const chromeIos = parsePhone(CHROME_IOS_FROZEN)!;
  assert.equal(chromeIos.os, 'iOS 18+');
  assert.equal(judgePhone(chromeIos).status, 'ok');
  assert.equal(parsePhone(IPAD_AS_MAC), null, 'a Mac without touch is not a tablet');
  const ipad = parsePhone(IPAD_AS_MAC, { touch: true })!;
  assert.deepEqual([ipad.platform, ipad.os, ipad.model], ['ipados', 'iPadOS 18', 'iPad']);
  assert.equal(parsePhone(PC), null);
});

test('merge: newest first, first-seen kept, battery as percent', () => {
  const info = parsePhone(CHROME_ANDROID, { platformVersion: '14', model: 'SM-S921B' })!;
  const a = mergeCheckin([], 'phone-aaaa1111', info, { battery: { level: 0.42, charging: true }, standalone: true }, 1000);
  assert.equal(a.rec.label, 'SM-S921B (Android)');
  assert.deepEqual([a.rec.battery, a.rec.charging, a.rec.standalone], [42, true, true]);
  const ipad = parsePhone(IPAD_AS_MAC, { touch: true })!;
  const b = mergeCheckin(a.list, 'ipad-bbbb2222', ipad, {}, 2000);
  const c = mergeCheckin(b.list, 'phone-aaaa1111', info, { battery: { level: 2 } }, 3000);
  assert.deepEqual(c.list.map((r) => r.id), ['phone-aaaa1111', 'ipad-bbbb2222']);
  assert.equal(c.rec.firstSeen, 1000);
  assert.equal(c.rec.battery, null, 'out-of-range battery ignored');
  assert.equal(c.before?.lastSeen, 1000);
});
