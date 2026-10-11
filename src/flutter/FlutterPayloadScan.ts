import { Buffer } from "node:buffer";

/**
 * Streaming scanners for Flutter payload libraries inside an APK.
 *
 * All facts are observations of byte patterns at read time: the Dart
 * snapshot hash sits 20 bytes after each snapshot magic, the GNU build-id
 * is an ELF note, and version facts are labeled ASCII strings. Nothing is
 * inferred or looked up externally.
 */

/** First index of `needle` in `haystack` at or after `from`, or -1. */
const findBytes = (
  haystack: Uint8Array,
  needle: Uint8Array,
  from: number,
): number => {
  if (needle.length === 0) return from;
  const last = haystack.length - needle.length;
  for (let index = from; index <= last; index += 1) {
    let matched = true;
    for (let probe = 0; probe < needle.length; probe += 1) {
      if (haystack[index + probe] !== needle[probe]) {
        matched = false;
        break;
      }
    }
    if (matched) return index;
  }
  return -1;
};

/** Magic starting every Dart VM and isolate snapshot section. */
export const DART_SNAPSHOT_MAGIC = Uint8Array.from([0xf5, 0xf5, 0xdc, 0xdc]);
const SNAPSHOT_HASH_OFFSET = 20;
const SNAPSHOT_HASH_LENGTH = 32;
const HASH_PATTERN = /^[0-9a-f]{32}$/u;

export interface SnapshotHashScan {
  /** Snapshot sections found. */
  readonly sources: number;
  /** Distinct 32-hex hashes following the magic, in first-seen order. */
  readonly candidates: readonly string[];
}

/**
 * Incremental scanner for Dart snapshot magics and the hash that follows.
 * Feed chunks in order; a trailing carry keeps a magic-to-hash span that a
 * chunk boundary would otherwise split.
 */
export class SnapshotHashScanner {
  #sources = 0;
  private readonly candidates: string[] = [];
  #buffer = new Uint8Array(0);
  /** Absolute stream offset from which unprocessed bytes begin. */
  #base = 0;
  #absoluteScanFrom = 0;

  push(chunk: Uint8Array): void {
    const joined = new Uint8Array(this.#buffer.length + chunk.length);
    joined.set(this.#buffer, 0);
    joined.set(chunk, this.#buffer.length);
    // Resume after the last fully processed hash so carried bytes are not
    // counted twice across chunk boundaries.
    let offset = Math.max(0, this.#absoluteScanFrom - this.#base);
    let pendingMagic: number | null = null;
    for (;;) {
      const magic = findBytes(joined, DART_SNAPSHOT_MAGIC, offset);
      if (magic === -1) break;
      if (magic + SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH > joined.length) {
        pendingMagic = magic;
        break;
      }
      const candidate = Buffer.from(
        joined.slice(
          magic + SNAPSHOT_HASH_OFFSET,
          magic + SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH,
        ),
      ).toString("latin1");
      if (HASH_PATTERN.test(candidate) && !this.candidates.includes(candidate))
        this.candidates.push(candidate);
      this.#sources += 1;
      offset = magic + DART_SNAPSHOT_MAGIC.length;
      this.#absoluteScanFrom =
        this.#base + magic + SNAPSHOT_HASH_OFFSET + SNAPSHOT_HASH_LENGTH;
    }
    // Keep a pending magic for the next chunk; otherwise keep only the
    // trailing bytes where a magic could still begin, so magic-free
    // streams never accumulate.
    const keepFrom =
      pendingMagic ??
      Math.max(
        this.#absoluteScanFrom - this.#base,
        joined.length - (DART_SNAPSHOT_MAGIC.length - 1),
      );
    this.#buffer = joined.slice(keepFrom);
    this.#base += keepFrom;
    if (pendingMagic !== null) this.#absoluteScanFrom = this.#base;
  }

  result(): SnapshotHashScan {
    return { sources: this.#sources, candidates: [...this.candidates] };
  }
}

/** GNU build-id note header: namesz=4, descsz (variable), type=3, "GNU\0". */
const BUILD_ID_NOTE_PREFIX_FIXED = Uint8Array.from([0x04, 0x00, 0x00, 0x00]);
const BUILD_ID_NOTE_TAIL = Uint8Array.from([
  0x03, 0x00, 0x00, 0x00, 0x47, 0x4e, 0x55, 0x00,
]);
/** Builds emit 8- or 20-byte ids; accept anything hex-printable in range. */
const BUILD_ID_MIN_BYTES = 4;
const BUILD_ID_MAX_BYTES = 64;
const BUILD_ID_PATTERN = /^[0-9a-f]{8,128}$/u;

/**
 * Incremental scanner for GNU build-id notes. Old toolchains emit 8-byte
 * ids and current ones 20 bytes, so the descriptor length is read from the
 * note header instead of assumed.
 */
export class BuildIdScanner {
  #buildId: string | null = null;
  #buffer = new Uint8Array(0);

  push(chunk: Uint8Array): void {
    if (this.#buildId !== null) return;
    const joined = new Uint8Array(this.#buffer.length + chunk.length);
    joined.set(this.#buffer, 0);
    joined.set(chunk, this.#buffer.length);
    // Scan every namesz=4 candidate; early bytes can collide with padding.
    let probe = 0;
    for (;;) {
      const prefix = findBytes(joined, BUILD_ID_NOTE_PREFIX_FIXED, probe);
      if (prefix === -1) break;
      if (prefix + 6 <= joined.length) {
        const described = joined[prefix + 4]! + joined[prefix + 5]! * 0x100;
        if (
          described >= BUILD_ID_MIN_BYTES &&
          described <= BUILD_ID_MAX_BYTES &&
          findBytes(joined, BUILD_ID_NOTE_TAIL, prefix + 8) === prefix + 8 &&
          prefix + 16 + described <= joined.length
        ) {
          const start = prefix + 16;
          const candidate = Array.from(
            joined.subarray(start, start + described),
            (byte) => byte.toString(16).padStart(2, "0"),
          ).join("");
          if (BUILD_ID_PATTERN.test(candidate)) {
            this.#buildId = candidate;
            break;
          }
        }
      }
      probe = prefix + 1;
    }
    // Keep enough trailing bytes for the fixed prefix plus one maximum note.
    const keep = Math.min(
      joined.length,
      4 + 2 + BUILD_ID_NOTE_TAIL.length + BUILD_ID_MAX_BYTES,
    );
    this.#buffer = joined.slice(joined.length - keep);
  }

  result(): string | null {
    return this.#buildId;
  }
}

/** Labeled strings worth reporting when a build carries them. */
export interface LabeledStringScan {
  readonly dartVersion: string | null;
  readonly toolchainLines: readonly string[];
}

const DART_VERSION_PATTERN = /Dart VM version:[^\x00\n]{0,200}/u;
const TOOLCHAIN_PATTERN =
  /Android \([^)\x00\n]{0,80}\) clang version [^\x00\n]{0,500}|based on LLVM \d[^\x00\n]{0,80}/u;
const MAX_TOOLCHAIN_LINES = 4;

/**
 * Incremental ASCII string collector that keeps only labeled version and
 * toolchain facts. Printable runs feed the patterns; a 256-byte carry
 * survives chunk boundaries.
 */
export class LabeledStringScanner {
  #dartVersion: string | null = null;
  private readonly toolchainLines: string[] = [];
  private carry = "";
  private printable: string = "";

  push(chunk: Uint8Array): void {
    let run = "";
    for (const byte of chunk) {
      if (byte >= 0x20 && byte < 0x7f) run += String.fromCharCode(byte);
      else {
        this.#consider(run);
        run = "";
      }
    }
    this.#consider(run, true);
  }

  #consider(run: string, partial = false): void {
    const text = this.carry + run;
    if (this.#dartVersion === null) {
      const match = DART_VERSION_PATTERN.exec(text);
      if (match !== null) this.#dartVersion = match[0].trim();
    }
    if (this.toolchainLines.length < MAX_TOOLCHAIN_LINES) {
      const match = TOOLCHAIN_PATTERN.exec(text);
      if (match !== null) {
        const line = match[0].trim();
        if (line !== "" && !this.toolchainLines.includes(line))
          this.toolchainLines.push(line);
      }
    }
    this.carry = partial ? text.slice(-256) : "";
  }

  result(): LabeledStringScan {
    return {
      dartVersion: this.#dartVersion,
      toolchainLines: [...this.toolchainLines],
    };
  }
}
