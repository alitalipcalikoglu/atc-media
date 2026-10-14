# Storage quotas

One key can fill the disk. Two guards stop that.

```bash
KEY_QUOTA_BYTES=atc-export:5368709120,atc-render:1073741824   # 5 GiB and 1 GiB
DEFAULT_QUOTA_BYTES=2147483648                                 # every other key: 2 GiB (0 = unlimited)
MIN_FREE_BYTES=2147483648                                      # refuse uploads below 2 GiB free on the data volume
```

## What counts

The bytes of the live files a key owns. Each file counts its full size, also when its bytes are shared with another file (deduplication saves disk, it does not give anyone extra quota). Soft-deleted files stop counting at once. Image variants are not counted (they are derived and regenerable).

## What happens at the limit

An upload that would take the key over its quota is refused while it streams (nothing is kept) with `507`:

```json
{ "error": { "code": "QUOTA_EXCEEDED", "message": "this upload would exceed the storage quota of 5368709120 bytes", "details": { "quotaBytes": 5368709120, "usedBytes": 5368000000 } } }
```

`STORAGE_FULL` (also `507`) means the volume itself has less than `MIN_FREE_BYTES` free. Upload tickets are checked the same way when the browser uploads, not when the ticket is issued.

## Reading usage

```bash
curl -s -H "Authorization: Bearer $KEY" $MEDIA/v1/usage
# { "keyId": "atc-export", "usedBytes": 2310000000, "quotaBytes": 5368709120, "maxUploadBytes": 20971520 }
```

`/metrics` has `media_stored_bytes` (all originals) and, with `MIN_FREE_BYTES` set, `media_storage_free_bytes`.

Pitfalls:
- Another service's quota (export files, backups, rendered PDFs) fills up silently: the service records the upload failure (`media_error` on a backup, a failed export job). Watch `usedBytes` against `quotaBytes`.
- A quota is per key id: two services sharing a key share the quota.
