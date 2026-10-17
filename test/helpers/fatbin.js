'use strict';

// A minimal host ELF with real cubin payloads, matching the Python fatbin fixture.
function hostWithCubins(...cubins) {
  const entries = cubins.map((cubin) => {
    const header = Buffer.alloc(64);
    header.writeUInt16LE(2, 0);
    header.writeUInt16LE(0x101, 2);
    header.writeUInt32LE(64, 4);
    header.writeBigUInt64LE(BigInt(cubin.length), 8);
    return Buffer.concat([header, cubin]);
  });
  const payload = Buffer.concat(entries);
  const fatHeader = Buffer.alloc(16);
  fatHeader.writeUInt32LE(0xba55ed50, 0);
  fatHeader.writeUInt16LE(1, 4);
  fatHeader.writeUInt16LE(16, 6);
  fatHeader.writeBigUInt64LE(BigInt(payload.length), 8);
  const fat = Buffer.concat([fatHeader, payload]);
  const names = Buffer.from('\0.shstrtab\0.nv_fatbin\0');
  const strOff = 128;
  const fatOff = (strOff + names.length + 7) & ~7;
  const shoff = (fatOff + fat.length + 7) & ~7;
  const host = Buffer.alloc(shoff + 3 * 64);
  Buffer.from('7f454c46020101000000000000000000', 'hex').copy(host);
  host.writeUInt16LE(1, 16);
  host.writeUInt16LE(62, 18);
  host.writeUInt32LE(1, 20);
  host.writeBigUInt64LE(BigInt(shoff), 40);
  host.writeUInt16LE(64, 52);
  host.writeUInt16LE(64, 58);
  host.writeUInt16LE(3, 60);
  host.writeUInt16LE(1, 62);
  names.copy(host, strOff);
  fat.copy(host, fatOff);
  for (const [index, name, type, flags, offset, size, align] of [
    [1, '.shstrtab', 3, 0, strOff, names.length, 1],
    [2, '.nv_fatbin', 1, 2, fatOff, fat.length, 8],
  ]) {
    const at = shoff + index * 64;
    host.writeUInt32LE(names.indexOf(name), at);
    host.writeUInt32LE(type, at + 4);
    host.writeBigUInt64LE(BigInt(flags), at + 8);
    host.writeBigUInt64LE(BigInt(offset), at + 24);
    host.writeBigUInt64LE(BigInt(size), at + 32);
    host.writeBigUInt64LE(BigInt(align), at + 48);
  }
  return host;
}

module.exports = { hostWithCubins };
