/**
 * Detects a file's real type from its leading bytes. The client-supplied Content-Type is a hint
 * only; the sniffed type decides what is stored and served.
 */
export class TypeSniffer {
  /** Bytes needed for a confident decision. */
  static HEAD_BYTES = 64;

  /** @type {Record<string, string>} */
  static EXTENSIONS = {
    'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif', 'image/avif': 'avif',
    'image/svg+xml': 'svg', 'application/pdf': 'pdf', 'text/csv': 'csv', 'application/x-ndjson': 'ndjson',
    'application/vnd.sqlite3': 'sqlite',
  };

  /** Text data types: bytes cannot tell them apart, so the declared file extension picks one. */
  static TEXT_TYPES = { csv: 'text/csv', ndjson: 'application/x-ndjson' };

  /**
   * @param {Buffer} head At least the first {@link HEAD_BYTES} bytes (or the whole file if shorter).
   * @returns {string|null} MIME type, or null when unrecognised.
   */
  static sniff(head) {
    if (head.length >= 3 && head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff) return 'image/jpeg';
    if (head.length >= 8 && head.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
    if (head.length >= 6 && (head.subarray(0, 6).toString('latin1') === 'GIF87a' || head.subarray(0, 6).toString('latin1') === 'GIF89a')) return 'image/gif';
    if (head.length >= 12 && head.subarray(0, 4).toString('latin1') === 'RIFF' && head.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
    if (head.length >= 12 && head.subarray(4, 8).toString('latin1') === 'ftyp') {
      const brand = head.subarray(8, 12).toString('latin1');
      if (brand === 'avif' || brand === 'avis') return 'image/avif';
    }
    if (head.length >= 5 && head.subarray(0, 5).toString('latin1') === '%PDF-') return 'application/pdf';
    if (head.length >= 16 && head.subarray(0, 16).toString('latin1') === 'SQLite format 3\0') return 'application/vnd.sqlite3';
    const text = head.toString('utf8').replace(/^﻿/, '').trimStart();
    if (/^<\?xml[\s\S]{0,200}?<svg[\s>]/i.test(text) || /^<svg[\s>]/i.test(text)) return 'image/svg+xml';
    return null;
  }

  /**
   * Text data type for a file the byte sniffer did not recognise: only when the declared name ends
   * in `.csv` / `.ndjson` and the leading bytes are text (no NUL, no other control bytes besides
   * tab/CR/LF, valid UTF-8). NDJSON must also start with `{` or `[`. Never inline-renderable.
   * @param {Buffer} head
   * @param {string|null|undefined} name Client-declared file name.
   * @returns {string|null}
   */
  static textType(head, name) {
    const ext = /\.([A-Za-z0-9]{1,8})$/.exec(name ?? '')?.[1]?.toLowerCase() ?? '';
    const mime = /** @type {Record<string, string>} */ (TypeSniffer.TEXT_TYPES)[ext];
    if (!mime) return null;
    if (head.some((b) => b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d) || head.includes(0x7f)) return null;
    // A full head may end inside a multi-byte character: stream mode tolerates only that, never invalid bytes.
    try { new TextDecoder('utf-8', { fatal: true }).decode(head, { stream: head.length >= TypeSniffer.HEAD_BYTES }); } catch { return null; }
    if (mime === 'application/x-ndjson' && head.length && !/^\s*[[{]/.test(head.toString('utf8').replace(/^\uFEFF/, ''))) return null;
    return mime;
  }

  /** @param {string} mime */
  static isImage(mime) {
    return mime.startsWith('image/') && mime !== 'image/svg+xml';
  }

  /**
   * Image formats sharp can decode and re-encode losslessly enough to normalise on upload.
   * @param {string} mime
   */
  static isRasterImage(mime) {
    return mime === 'image/jpeg' || mime === 'image/png' || mime === 'image/webp' || mime === 'image/gif' || mime === 'image/avif';
  }

  /**
   * @param {string} mime
   * @returns {string}
   */
  static extension(mime) {
    return TypeSniffer.EXTENSIONS[mime] ?? 'bin';
  }
}
