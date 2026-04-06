# File Type Analyser

A cross-platform desktop application that identifies the true type of any file using multiple independent analysis techniques — going well beyond the file extension alone.

## How to use

- **Drag & drop** one or more files (or a whole folder) directly onto the drop zone.
- Click **Open File(s)** to pick individual files with a system file dialog.
- Click **Open Folder** to recursively scan every file inside a folder.
- Results appear as expandable cards showing the detected type, overall confidence, and per-method breakdowns.
- Click **Save Results (.txt)** to export the full report with ISO 8601 timestamps.
- Click **Clear** to reset and analyse a new batch.

## Confidence levels

| Level | Range | Meaning |
|-------|-------|---------|
| High | ≥ 70 % | Strong agreement across multiple methods |
| Medium | 40 – 69 % | Partial evidence; result is a best guess |
| Low | < 40 % | Inconclusive; treat with caution |

## Technical details

- Built with **Tauri v2** (Rust backend) and a plain JavaScript / Vite frontend.
- All analysis is performed locally — no data leaves your machine.
- The six analysis methods run in parallel and their results are fused by weighted voting.

## Privacy & safety

- This application is **strictly read-only**. It only reads the bytes of the files you submit for analysis — it never writes to, modifies, moves, renames, or deletes them.
- The only file written to disk is the optional report you explicitly export via **Save Results (.txt)**, saved to a location of your choosing.
- No network requests are made. All processing happens entirely on your local machine.

## A-TIME

The application itself makes no metadata modifications. However, the **operating system** may update a file's **atime** (last-access timestamp) as a side effect of any read operation.

- **Linux:** Most modern systems use `relatime` (only updates atime if it's older than mtime) or `noatime`, so reads typically do not change atime in practice.
- **Windows (NTFS):** Last-access time tracking is disabled by default on modern Windows, so atime is generally not updated.
- **macOS (HFS+/APFS):** Behaves similarly to Linux `relatime`.

Beyond this possible OS-level atime touch, the app alters nothing.

---

## Analysis Methods

Each file is examined by all six methods independently. The per-method confidence scores are combined to produce the final result.

### 1. File Signatures (Magic Bytes)

Reads the first few bytes (and sometimes a trailer) of a file and compares them against a database of known magic-byte sequences. Most file formats embed a unique byte pattern — for example, PDF files begin with `%PDF`, PNG images with `\x89PNG`, and ZIP archives with `PK\x03\x04`. Because this check is purely structural, it is the fastest and most reliable single indicator of file type.

### 2. Byte Frequency Analysis

Counts how often each of the 256 possible byte values (0x00 – 0xFF) appears across the whole file and builds a frequency histogram. Different file categories have characteristic distributions: plain-text files cluster heavily around printable ASCII values, compressed or encrypted data shows a near-uniform distribution (high entropy), binary executables have a spike of null bytes, and image formats produce medium-entropy histograms unique to their codec. This method works without any format knowledge and is effective on files whose magic bytes are missing or corrupted.

### 3. Byte Frequency Cross-correlation

Extends byte-frequency analysis by computing the statistical similarity (cross-correlation) between the file's byte histogram and pre-computed reference histograms from a library of known file types. The reference library is built from many representative samples, so the correlation captures not just the overall entropy level but also the fine-grained shape of the distribution. This makes it possible to distinguish, for instance, a JPEG from a PNG even though both are image formats with similar entropy.

### 4. File Header / Trailer Analysis

Scans a window at the start and end of a file for human-readable or structured markers that identify the format. Many formats include version strings, XML declarations, shebang lines, or closing markers that are distinct even when the magic bytes are absent. For example, a shell script starts with `#!/bin/sh`, an HTML file may begin with `<!DOCTYPE html>`, and a ZIP archive always ends with the end-of-central-directory signature `PK\x05\x06`. This method complements magic-byte detection and catches container formats that embed their signature deep inside the header.

### 5. N-gram Analysis

Extracts short overlapping byte sequences (n-grams, typically 2- or 3-byte windows) from a sample of the file and computes their frequency distribution. N-gram profiles are highly characteristic: source-code files show recurring identifier fragments, natural-language text files show common digrams/trigrams of written language, binary formats repeat opcode or data-length patterns. The observed profile is compared against reference profiles for each known type using a distance metric (e.g., rank-order distance), and the closest match contributes a confidence score.

### 6. Strings & Keyword Analysis

Extracts printable ASCII and UTF-8 strings of a minimum length from the binary content and searches them for format-specific keywords and patterns. Examples include XML tag names, JSON delimiters, MIME type strings, copyright notices, compiler artefacts, script interpreters, and format-specific identifiers like `SQLite format 3` or `IHDR` / `IDAT` chunks in PNG streams. This method is particularly effective for text-based and structured formats, and it can identify polyglot or embedded content (e.g., HTML embedded inside a PDF).

---

## Release

[https://github.com/andresele/OdgFileType/releases](https://github.com/andresele/OdgFileType/releases)
