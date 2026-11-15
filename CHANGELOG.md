# Changes

## 0.2.2

Lguard damaged its own inventory - fixed
- From 0.2.0 on, the service could destroy its inventory (`index.db`) within
  a day or two of running: every changed file reaches the service as an open
  descriptor that it has to close, and that included the inventory itself
  whenever a nightly check or a full disk scan had used it. Closing such a
  descriptor drops the locks the database holds, the next process to finish
  then deleted the database's log, and from there on scans failed with
  "database disk image is malformed" or "disk I/O error", the nightly check
  stopped at once and the app got no answer - all without a word to the user.
  The service now switches those events off in the kernel and never closes a
  descriptor of its own files.
- **After updating**, a damaged inventory is found at the first start and
  replaced by a new one. Your decisions (trusted and removed content, files
  waiting for you, a freeze in force) and the history are carried over as far
  as they can be read; the list of files is not, so every file is checked
  again once. The damaged file is kept as `index.db.damaged` until the next
  time this happens.

Lguard notices when it is not working
- Every part of the service is supervised. If one stops, or the inventory
  turns out to be damaged while running, you get an alert and the service
  restarts itself; "real-time: on" is reported only while all parts run.
- The nightly check reads every page of the inventory before it starts, and
  a check that stops with an error sends an alert instead of failing quietly.

Files that could stop the service
- A file that is mostly holes (a few exabytes long, taking no room) kept a
  scan worker reading for good; two of them ended real-time scanning. Such a
  file gets its beginning and end checked and is recorded as "partial",
  never as clean. Reading one file through is given at most an hour.
- A program whose name is not valid text could end the thread that receives
  file events.
- A file name that is not valid UTF-8 made the alert fail (the file was
  quarantined, but nobody was told), ended a scan worker and stopped the
  nightly check at that file every night. Such bytes are now shown as `\xNN`.
- One file that cannot be checked no longer ends the whole check.
- A file really named "... (deleted)" was neither scanned on change nor
  could it be quarantined.

Smaller
- The settings (`/etc/lguard/lguard.toml` and the app's drop-in) are readable
  by root only: they can hold the address alerts are sent to. `lguard status`
  without root asks the service, as before.
- App: a file name starting with "-" was read by `notify-send` as an option;
  paths, program names and signers are shown as plain text, never as markup.
- `lguard status` no longer counts the whole inventory on every call from
  the app.

## 0.2.1

False alarms
- A detection in a file that has not changed for 30 days (`hold_old_days`),
  met by the nightly check or the full disk scan, is reported and left where
  it is until you decide. Before, it was moved to quarantine at once: one
  wrong signature could break a working program, and where a folder is
  synced the removal travelled on to the other copies. New and changed
  files, everything in the category folders and content you already removed
  once are quarantined at once, as before.
- A file left in place is quarantined the moment it is started as a program
  (Linux 5.0+).
- Windows programs: Lguard reads the publisher signature of a detected file.
  If the content is still exactly what was signed, the finding says so
  (often a false alarm). If it was changed after signing, the file is
  quarantined however old it is. The signature is evidence, not a pass: the
  certificate chain is not verified, so a signed new file is still
  quarantined.
- One decision for every copy: "Trust" restores all quarantined copies of
  the same content and keeps the ones left in place; "Delete" removes all of
  them, and later copies of that content are quarantined without asking.
  One alert per content instead of one per copy.
- App: new tab "Waiting for you" under Findings; "All findings" shows what
  became of each. Command line: `lguard held list | trust | quarantine |
  delete <sha256>`.

## 0.2.0

Security
- Quarantine and restore no longer trust a path inside a user's folder: the
  folder is opened without following links and every step works on open
  descriptors. A folder swapped for a link at the wrong moment can no longer
  make Lguard move, delete or hand over another file.
- The local socket gives an unknown caller very little: request size,
  connections in total and per user are limited.
- A pause longer than three hours needs the administrator password, and no
  pause lasts longer than a day.
- The scan engine runs without network, cannot write its own signatures and
  sees no home folder. The signature updater no longer starts as root.
- A program that only carries the name of a trusted one (a copy of `rsync`
  in a temp folder) is no longer exempt from the ransomware shield.
- A damaged or hand-edited inventory record can no longer stop the service.
- Release packages carry a signed build provenance.

Detection
- Files renamed into place are scanned at once (browser downloads, download
  clients). Needs Linux 5.9; older systems re-check the folder instead.
- Programs in cache, log and database folders are scanned; before, those
  folders were skipped entirely.
- The full disk scan now runs the engine again on every file, not only a
  comparison of checksums. Files of unknown type and active documents (HTML,
  RTF, SVG, mail, OneNote) get new signatures while they are new.
- Archives, installers and disk images are scanned whole up to 2 GB. What the
  engine cannot go through completely is recorded as "partly checked".
- Disks mounted after start (USB sticks) are watched and checked.
- Ransomware shield: catches encryption to a new name with the original
  deleted, and encryption of only the beginning of a file; knows more
  formats; suspends a program that is not part of the system; alarms again
  if backups were unfrozen while the attack goes on.

Changed
- The download category is called **Downloads**; an existing `torrents`
  category is read as `downloads`. Rule names are `Lguard.Media.*`.
- Every category is a *media library* (programs are quarantined) or a
  *downloads* folder (programs are normal). Disk images are reported, never
  quarantined. TypeScript `.ts` files are no longer taken for fake videos.
- The nightly check and a full disk scan no longer cancel each other.
- New signatures no longer cause every program and document on the disk to
  be scanned again each night; old files are re-checked in rotation.
- After an unclean stop the changed files are checked at once instead of at
  the next nightly run.
- `lguard status` works without root. New: `lguard trust`, `lguard
  resume-process`.
- App: new look (neutral dark with a steel sheen, clean light theme, one blue
  accent) with the Inter and Cascadia Mono fonts bundled, so it looks the same
  on every desktop.
- An administrator password entered in the app holds for five minutes (for
  that app window only), instead of being asked for every single action.
- App: the scan button and the progress bar show what is really happening:
  the bar moves only while something is scanned, a running scan is greyed out
  and cannot be started twice. New About page; the header menu is gone.
- App: trust can be removed; folders protected by the ransomware shield and
  the mode of each category can be set; no double notifications.
- Daily counters are written in batches (one write every few seconds instead
  of one per file).
- Automated tests.
