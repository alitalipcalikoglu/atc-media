# Virus scan and quarantine

Scan every upload with ClamAV and keep what it rejects for review.

## Setup

Run clamd next to the service (for example the `clamav/clamav` image, which listens on TCP 3310) and set:

```
CLAMD_HOST=127.0.0.1
CLAMD_PORT=3310
CLAMD_TIMEOUT_MS=30000
SCAN_FAIL_OPEN=false
QUARANTINE_DAYS=30
ADMIN_KEYS=ops-console
```

`ADMIN_KEYS` names key ids from `MEDIA_API_KEYS`; only those keys can see the quarantine. `/ready` now also pings clamd, so a stopped clamd takes the instance out of rotation.

## A clean upload

Nothing changes for callers: the file is streamed to clamd (`INSTREAM`) after the type check and before it is stored.

```bash
curl -X PUT "$MEDIA/v1/files?name=report.pdf" -H "Authorization: Bearer $KEY" --data-binary @report.pdf
```

`201` with `{ "file": { …, "owner": "shop-backend" } }`.

## An infected upload

The EICAR test string is the safe way to try it (save it as `eicar.csv` with `text/csv` in `ALLOWED_TYPES`, or upload any allowed type that contains it):

```bash
curl -X PUT "$MEDIA/v1/files?name=eicar.csv" -H "Authorization: Bearer $KEY" --data-binary @eicar.csv
```

```json
{ "error": { "code": "INFECTED", "message": "the file contains malware (Eicar-Test-Signature); it was quarantined",
  "details": { "quarantineId": "q_mgx1k2abc0123456789ab", "signature": "Eicar-Test-Signature" } } }
```

Status `422`. No file record is created, the key's quota is not charged, and the bytes move to `DATA_DIR/quarantine/<id>`. They are never served.

## Review the quarantine (admin key)

```bash
curl "$MEDIA/v1/quarantine" -H "Authorization: Bearer $ADMIN_KEY"
```

```json
{ "items": [ { "id": "q_mgx1k2abc0123456789ab", "owner": "shop-backend", "name": "eicar.csv", "mime": "text/csv",
  "size": 68, "sha256": "275a02…", "signature": "Eicar-Test-Signature", "createdAt": "2026-10-16T09:12:00.000Z" } ] }
```

Delete one after review (`204`); maintenance removes the rest after `QUARANTINE_DAYS`:

```bash
curl -X DELETE "$MEDIA/v1/quarantine/q_mgx1k2abc0123456789ab" -H "Authorization: Bearer $ADMIN_KEY"
```

A non-admin key gets `403 FORBIDDEN` on both routes.

## Admin keys and other keys' files

Admin keys list every key's files and can narrow by owner:

```bash
curl "$MEDIA/v1/files?owner=shop-backend&limit=50" -H "Authorization: Bearer $ADMIN_KEY"
```

They can also rename, delete and restore those files. A non-admin key's `owner` filter is ignored; it only ever sees its own files.

## When clamd is down

Default (`SCAN_FAIL_OPEN=false`): uploads are refused with `503 SCAN_UNAVAILABLE` and nothing is stored, so retry later. With `SCAN_FAIL_OPEN=true` uploads are accepted unscanned and the service logs `virus scan unavailable` for each one.

## Pitfalls

- clamd's `StreamMaxLength` (default 25 MB) must be at least `MAX_UPLOAD_BYTES` and every `KEY_MAX_UPLOAD_BYTES`; otherwise clamd answers with a size error and the upload is refused as `SCAN_UNAVAILABLE`.
- The scan runs on the stored temp file, after type sniffing: a file of a type outside `ALLOWED_TYPES` is rejected with `415` before it is scanned.
- Files uploaded before the scan was turned on are not rescanned.
