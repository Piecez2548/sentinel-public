import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseStatusSpec, statusMatches } from './checker.js';

test('parseStatusSpec accepts codes and ranges', () => {
  assert.deepEqual(parseStatusSpec('401'), [[401, 401]]);
  assert.deepEqual(parseStatusSpec('200-299, 401'), [[200, 299], [401, 401]]);
});

test('parseStatusSpec rejects bad input', () => {
  for (const bad of ['', 'abc', '99', '600', '300-200', '200-', '2000', '1,2,3,4,5,6,7,8,9,10,11'.split(',').map(() => '200').join(',')]) {
    assert.equal(parseStatusSpec(bad), null, bad);
  }
});

test('statusMatches', () => {
  const spec = parseStatusSpec('200-299,401')!;
  assert.equal(statusMatches(401, spec), true);
  assert.equal(statusMatches(204, spec), true);
  assert.equal(statusMatches(500, spec), false);
  assert.equal(statusMatches(403, spec), false);
});
