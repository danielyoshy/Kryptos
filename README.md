# cenc — passphrase file encryption (AES-256-GCM + Argon2id)

```
pip install -r requirements.txt
```

## Desktop app

```
python cenc_gui.py          # or double-click "CENC Vault.bat"
```

A dark-gray Tkinter desktop app (no extra dependencies) with seven tabs:

* **Vault Files:** store files directly in the app's local `vault_storage/` folder, filter
  between **All Files**, **Encrypted (.enc)**, and **Unencrypted**, search by filename, and
  encrypt, decrypt, inspect, export, or securely delete stored files in one click. Classification
  checks the actual `CENC` binary header rather than trusting the `.enc` extension alone.
* **Create File:** write a new text file directly inside the app's built-in editor **or upload an
  image, video, or PDF** (PNG, JPG, GIF, BMP, TIFF, ICO, MP4, MOV, AVI, MKV, WEBM, WMV, PDF, etc.)
  with a preview card, choose whether to store it in the local Vault or any folder on your computer,
  and stream-encrypt it into a `.enc` container—or save it unencrypted to encrypt later.
* **Encrypt:** pick any file (or an already-encrypted `.enc` file to wrap it in another encryption
  layer), password (with strength hint and a Show toggle), key-derivation function, and **Layers to
  apply** (`1..10`, e.g. `.enc`, `.enc.enc`, `.enc.enc.enc`). When encryption completes and the new
  `.enc` container is verified, the original file is **automatically wiped and deleted** without any
  confirmation popups. Click **Encrypt Output Again (+1 Layer)** (or **Add Layer (.enc)** in
  **Vault Files**) to re-encrypt an encrypted file with the same or a different password.
* **Decrypt:** pick a `.enc` (or multi-layer `.enc.enc...`) file and password; once the file is
  authenticated and restored, the encrypted `.enc` file is **automatically wiped and deleted** and
  replaced with the restored file without any confirmation popups. When decrypting a multi-layer
  file, peeling the outer layer automatically replaces the `.enc.enc` file with the inner `.enc`
  container and queues it for the next password—or tick **Unwrap all encryption layers that use
  this password** to unwrap multiple layers in one click.
* **Inspect / Verify:** view a file's header without a password, or verify the password
  and integrity without writing anything.
* **Hash Check:** compute a file's hash (SHA-256, SHA-512, SHA3-256, BLAKE2b) and optionally
  compare it with an expected checksum. Result is a clear MATCH / MISMATCH.
* **Baseline:** record the hashes of a file or folder, then later check for modified, missing
  and new files. See [File integrity](#file-integrity).

A progress bar and **Cancel** button are shared across tabs, and an activity log records what
happened. Work runs on a background thread, so the window never freezes. Cancelling
leaves your original untouched and removes any partial output. Passwords are cleared from
the form after each operation.

## File integrity

`integrity.py` (also built into the app's **Hash Check** and **Baseline** tabs) checks whether
*any* file, not just `.enc` files, has been altered.

```
python integrity.py hash   setup.exe                          # print SHA-256
python integrity.py hash   setup.exe --expect sha256:9f86d0…  # compare with a published checksum
python integrity.py baseline  C:\data\photos --protect        # record hashes of a folder
python integrity.py check     C:\data\photos.baseline.json    # what changed since then?
```

* **Hash check:** `--expect` accepts a bare hash, `sha256:<hash>`, `sha256sum` output
  (`<hash>  filename`), or a hash grouped with spaces/colons. Use `-a sha512|sha3_256|blake2b`
  for other algorithms. MD5 and SHA-1 are intentionally not offered.
* **Baseline:** stores each file's relative path, size and hash in `NAME.baseline.json`
  (next to the target by default). `check` then reports every file as `UNCHANGED`, `MODIFIED`,
  `MISSING`, or (for folders) `NEW`. Hash comparisons are constant-time.
* **Why `--protect` matters:** a plain baseline only proves a file differs from what was
  recorded. Anyone who can change the files can also rewrite an unprotected baseline to match.
  With `--protect` the baseline is sealed with an HMAC-SHA256 keyed from your password
  (Argon2id/PBKDF2, same as encryption), so any edit to it, such as changing a hash, adding or
  removing a file, or swapping the whole baseline for a forged one, is detected, and checking
  needs the password. The tool tells you whether a baseline was authenticated.
* Keep the baseline somewhere the files' potential attacker can't write to (another drive,
  a USB stick, or a copy you've emailed to yourself); the password protects against edits, but
  not against someone simply deleting it.

## Command line

```
python cenc.py encrypt report.pdf              # -> report.pdf.enc  (report.pdf is wiped and deleted)
python cenc.py decrypt report.pdf.enc          # -> report.pdf
python cenc.py verify  report.pdf.enc          # check password + integrity, write nothing
python cenc.py info    report.pdf.enc          # print header, no password needed

# options
  -o/--output PATH      choose the output path
  -f/--force            overwrite an existing output file
  -k/--keep             (encrypt only) keep the original instead of deleting it
  --kdf argon2id|pbkdf2 (encrypt only) choose the key-derivation function
```

The password is always entered with `getpass` (it's never echoed and never passed on the command line).

> **There is no recovery without the password.** After encryption, decrypting the `.enc` file
> is the only way to get the original back.

## Original-file deletion

When encryption succeeds, the tool:

1. writes the `.enc` file (to a temporary file that is renamed into place),
2. re-reads it and checks its authentication tag with the derived key,
3. **only then** overwrites the original with random bytes and deletes it.

If any step fails (wrong password confirmation, disk full, failed verification, existing
output), the original is left untouched. If the original can't be deleted (for example,
it's open in another program), the `.enc` file is kept, a warning is printed, and the
exit code is 5.

> **Limits of secure deletion.** Overwriting before deleting is best-effort.
> SSD wear-levelling, file-system journaling, backups/shadow copies, and **cloud sync
> (OneDrive keeps version history and a recycle bin)** can all keep copies of the original
> that this tool can't reach. For sensitive files, encrypt them *before* they ever land in
> a synced folder.

## Container format

| Offset | Size | Field      | Notes                                              |
|-------:|-----:|------------|----------------------------------------------------|
| 0      | 4    | Magic      | `b"CENC"`                                          |
| 4      | 1    | Version    | `0x01` Argon2id, `0x02` PBKDF2-HMAC-SHA256         |
| 5      | 16   | Salt       | random for each file                               |
| 21     | 12   | Nonce      | random for each encryption                         |
| 33     | n    | Ciphertext | AES-256-GCM, same length as the plaintext          |
| 33+n   | 16   | Tag        | GCM authentication tag                             |

* The 33-byte header is passed to GCM as associated data, so changing any header byte
  makes authentication fail.
* KDF parameters are fixed for each version:
  * v1: Argon2id, t=3, m=64 MiB, p=4 (RFC 9106 recommendation)
  * v2: PBKDF2-HMAC-SHA256, 600,000 iterations
  * v2 is only used when Argon2id isn't available.
* Passphrases are NFC-normalised UTF-8, so the same passphrase gives the same key on every OS.

## Behaviour notes

* **Streaming:** files are processed in 1 MiB chunks, so memory use stays constant.
  AES-GCM limits a single message to about 64 GiB.
* **No partial output:** results go to a temporary `.part` file and are only renamed into
  place once encryption or decryption has fully succeeded. If decryption fails, no
  unauthenticated plaintext is left on disk.
* **Wrong password vs. tampering:** AES-GCM can't tell these apart, because both just
  produce a tag mismatch. The tool reports one authentication error that covers both.
* **Exit codes:**

  | Code | Meaning                        |
  |-----:|--------------------------------|
  | 0    | success                        |
  | 1    | general / I/O error            |
  | 2    | usage error                    |
  | 3    | invalid or unsupported format  |
  | 4    | authentication failed          |
  | 5    | encrypted, but original could not be deleted |
  | 6    | `integrity.py`: hash mismatch, or changes found |
  | 7    | `integrity.py`: baseline password wrong or baseline altered |
  | 130  | interrupted                    |

## Tests

```
python -m unittest -v test_cenc
```
