import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';

/** Validate and read the same descriptor; never stat a name then reopen it. */
export function readControlledFile(path, label, maximumBytes) {
  if (!Number.isInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 16 * 1024 * 1024) {
    throw new Error(`${label} read bound is invalid`);
  }
  if (!Number.isInteger(constants.O_NOFOLLOW) || !Number.isInteger(constants.O_NONBLOCK)) {
    throw new Error('controlled file reads require no-follow, nonblocking open support');
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile()) throw new Error(`${label} must be a regular file`);
    if ((before.mode & 0o222) !== 0) throw new Error(`${label} must be read-only`);
    if (before.size < 1 || before.size > maximumBytes) throw new Error(`${label} must be bounded`);
    const buffer = Buffer.alloc(before.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = readSync(fd, buffer, length, buffer.length - length, null);
      if (read === 0) break;
      length += read;
    }
    const after = fstatSync(fd);
    if (length !== before.size || length > maximumBytes || after.size !== before.size
        || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs
        || after.mode !== before.mode) {
      buffer.fill(0);
      throw new Error(`${label} changed during its bounded read`);
    }
    return buffer.subarray(0, length);
  } finally { closeSync(fd); }
}
