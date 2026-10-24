import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readControlledFile } from '../src/controlled-file.mjs';

test('controlled reads bind metadata and bounded bytes to one read-only descriptor', () => {
  const root = mkdtempSync(join(tmpdir(), 'elmpay-controlled-'));
  const path = join(root, 'policy.json');
  try {
    writeFileSync(path, '{"default":"deny"}', { mode: 0o400 });
    assert.equal(readControlledFile(path, 'policy', 64).toString(), '{"default":"deny"}');
    assert.throws(() => readControlledFile(path, 'policy', 4), /bounded/);
    chmodSync(path, 0o600);
    assert.throws(() => readControlledFile(path, 'policy', 64), /read-only/);
    assert.throws(() => readControlledFile(root, 'policy', 64), /regular/);
    assert.throws(() => readControlledFile(path, 'policy', 0), /bound/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('controlled policy paths reject symlink substitution and empty files', () => {
  const root = mkdtempSync(join(tmpdir(), 'elmpay-controlled-'));
  const path = join(root, 'policy.json');
  const link = join(root, 'substituted.json');
  try {
    writeFileSync(path, 'secret fixture', { mode: 0o400 });
    symlinkSync(path, link);
    assert.throws(() => readControlledFile(link, 'policy', 64));
    chmodSync(path, 0o600);
    writeFileSync(path, '');
    chmodSync(path, 0o400);
    assert.throws(() => readControlledFile(path, 'policy', 64), /bounded/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
