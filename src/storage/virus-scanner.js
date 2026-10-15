import { createReadStream } from 'node:fs';
import { connect } from 'node:net';

/**
 * Virus scan through a ClamAV daemon (clamd) over TCP, with the INSTREAM command: the bytes are
 * streamed in length-prefixed chunks and clamd answers `stream: OK` or `stream: <Signature> FOUND`.
 * No dependency; clamd itself runs as its own service (e.g. the clamav/clamav image).
 */
export class VirusScanner {
  static CHUNK = 64 * 1024;

  /** @param {{ host: string, port: number, timeoutMs: number }} o */
  constructor({ host, port, timeoutMs }) {
    this.host = host;
    this.port = port;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Scan a local file.
   * @param {string} path
   * @returns {Promise<{ clean: true } | { clean: false, signature: string }>}  Rejects when clamd cannot be asked.
   */
  scan(path) {
    return new Promise((resolve, reject) => {
      const socket = connect({ host: this.host, port: this.port });
      let answer = '';
      let settled = false;
      const done = (/** @type {Error|null} */ err, /** @type {any} */ value) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        if (err) reject(err); else resolve(value);
      };
      socket.setTimeout(this.timeoutMs, () => done(new Error(`clamd did not answer within ${this.timeoutMs}ms`), null));
      socket.on('error', (err) => done(new Error(`clamd: ${err.message}`), null));
      socket.on('data', (d) => { answer += d.toString('utf8'); });
      socket.on('end', () => {
        const line = answer.replace(/\0/g, '').trim();
        if (/^stream: OK$/.test(line)) done(null, { clean: true });
        else if (/ FOUND$/.test(line)) done(null, { clean: false, signature: line.replace(/^stream: /, '').replace(/ FOUND$/, '').slice(0, 200) });
        else done(new Error(`clamd: ${line.slice(0, 200) || 'empty answer'}`), null);
      });
      socket.once('connect', () => {
        socket.write('zINSTREAM\0');
        const file = createReadStream(path, { highWaterMark: VirusScanner.CHUNK });
        file.on('data', (chunk) => {
          const size = Buffer.alloc(4);
          size.writeUInt32BE(chunk.length);
          if (!socket.write(Buffer.concat([size, /** @type {Buffer} */ (chunk)]))) { file.pause(); socket.once('drain', () => file.resume()); }
        });
        file.on('end', () => socket.write(Buffer.alloc(4))); // a zero-length chunk ends the stream
        file.on('error', (err) => done(err, null));
      });
    });
  }

  /** Readiness: clamd answers PING. */
  ping() {
    return new Promise((resolve, reject) => {
      const socket = connect({ host: this.host, port: this.port });
      let answer = '';
      socket.setTimeout(this.timeoutMs, () => { socket.destroy(); reject(new Error('clamd did not answer PING')); });
      socket.on('error', (err) => { socket.destroy(); reject(new Error(`clamd: ${err.message}`)); });
      socket.on('data', (d) => { answer += d.toString(); });
      socket.on('end', () => (answer.replace(/\0/g, '').trim() === 'PONG' ? resolve(undefined) : reject(new Error('clamd did not answer PONG'))));
      socket.once('connect', () => socket.end('zPING\0'));
    });
  }
}
