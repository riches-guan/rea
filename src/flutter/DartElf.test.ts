import { describe, expect, it } from "vitest";

import { readElfSymbol, readSnapshotHeader } from "./DartElf.js";

/**
 * Build a minimal real ELF64 little-endian image with one PT_LOAD segment
 * and a dynamic symbol table naming the Dart snapshot sections. This keeps
 * the golden tests self-contained instead of reading the author's disk.
 */
const buildElf64Image = (
  symbols: ReadonlyArray<{ name: string; value: number; size: number }>,
): Buffer => {
  const ELF_HEADER = 64;
  const PHENT = 56;
  const PHNUM = 1;
  const SHENT = 64;
  const phoff = ELF_HEADER;
  const shoffAligned = phoff + PHENT * PHNUM;
  // Place payload data after the three section headers so nothing overlaps.
  const dynsymOff = shoffAligned + 3 * SHENT + 16;
  const dynstrOff = dynsymOff + symbols.length * 24;
  const image = Buffer.alloc(dynstrOff + 256);
  // ELF header
  image.writeUInt32LE(0x464c457f, 0);
  image[4] = 2; // ELFCLASS64
  image[5] = 1; // little-endian
  image.writeUInt16LE(0x003e, 0x12); // e_machine x86_64
  image.writeUInt32LE(1, 0x10); // ET_REL? keep type small
  image.writeBigUInt64LE(BigInt(phoff), 0x20);
  image.writeBigUInt64LE(BigInt(shoffAligned), 0x28);
  image.writeUInt16LE(PHENT, 0x36);
  image.writeUInt16LE(PHNUM, 0x38);
  image.writeUInt16LE(SHENT, 0x3a);
  image.writeUInt16LE(2, 0x3c); // e_shnum: null + dynsym
  // Program header: one PT_LOAD mapping identity
  const ph = phoff;
  image.writeUInt32LE(1, ph); // PT_LOAD
  image.writeBigUInt64LE(BigInt(0), ph + 8); // vaddr
  image.writeBigUInt64LE(BigInt(0), ph + 0x08); // offset (overlaps vaddr)
  // Section headers
  const sh = shoffAligned;
  // null section stays zero
  const dyn = sh + SHENT;
  image.writeUInt32LE(11, dyn + 4); // SHT_DYNSYM
  image.writeBigUInt64LE(BigInt(dynsymOff), dyn + 0x18);
  image.writeBigUInt64LE(BigInt(symbols.length * 24), dyn + 0x20);
  image.writeUInt32LE(2, dyn + 0x28); // sh_link -> strtab section index
  // dynstr section header
  const str = dyn + SHENT;
  image.writeUInt32LE(3, str + 4); // SHT_STRTAB
  image.writeBigUInt64LE(BigInt(dynstrOff), str + 0x18);
  image.writeBigUInt64LE(BigInt(256), str + 0x20);
  image.writeUInt16LE(3, 0x3c); // e_shnum includes strtab
  // dynstr: leading NUL then names
  let strCursor = dynstrOff + 1;
  const nameOffsets = symbols.map((symbol) => {
    image.write(symbol.name, strCursor, "latin1");
    const at = strCursor - dynstrOff;
    strCursor += symbol.name.length + 1;
    return at;
  });
  // dynsym entries
  symbols.forEach((symbol, index) => {
    const base = dynsymOff + index * 24;
    image.writeUInt32LE(nameOffsets[index]!, base);
    image.writeBigUInt64LE(BigInt(symbol.value), base + 8);
    image.writeBigUInt64LE(BigInt(symbol.size), base + 16);
    image[base + 4] = 0x10; // GLOBAL FUNC
  });
  return image;
};

const GALLERY_HASH = "65817c30a78bb44c3dc3771876b6010a";

const snapshotSection = (hash: string): Buffer =>
  Buffer.concat([
    Buffer.from([
      0xf5, 0xf5, 0xdc, 0xdc, 0x49, 0x0d, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0,
      0,
    ]),
    Buffer.from(hash, "latin1"),
  ]);

const imageWithSections = (): Buffer => {
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x1000, size: 52 },
    { name: "_kDartIsolateSnapshotData", value: 0x2000, size: 52 },
  ]);
  const section = snapshotSection(GALLERY_HASH);
  return Buffer.concat([
    elf,
    Buffer.alloc(0x1000 - elf.length),
    section,
    Buffer.alloc(0x2000 - 0x1000 - section.length),
    section,
  ]);
};

describe("readElfSymbol", () => {
  it("locates snapshot symbols in a synthetic ELF64 image", () => {
    const image = imageWithSections();
    const isolateData = readElfSymbol(image, "_kDartIsolateSnapshotData");
    if ("failure" in isolateData) throw new Error(isolateData.failure.reason);
    expect(isolateData.symbol.offset).toBe(0x2000);
    expect(isolateData.symbol.size).toBe(52);
    const header = readSnapshotHeader(image, isolateData.symbol.offset);
    expect(header.magicValid).toBe(true);
    expect(header.kind).toBe(3);
  });

  it("refuses a non-ELF image instead of guessing", () => {
    const result = readElfSymbol(Buffer.from("not an elf at all"), "x");
    expect("failure" in result && result.failure.reason).toBe(
      "not an ELF image",
    );
  });

  it("refuses an unknown symbol", () => {
    const result = readElfSymbol(buildElf64Image([]), "_kDartAbsent");
    expect("failure" in result).toBe(true);
  });
});

describe("readSnapshotHeader", () => {
  it("reads a synthesized data header", () => {
    const header = readSnapshotHeader(snapshotSection(GALLERY_HASH), 0);
    expect(header.magicValid).toBe(true);
    expect(header.kind).toBe(3);
  });

  it("reports nulls for sections without the data magic", () => {
    const header = readSnapshotHeader(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]), 0);
    expect(header).toEqual({
      magicValid: false,
      kind: null,
      headerLength: null,
    });
  });
});
