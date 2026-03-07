use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// ─── Data structures ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeProposal {
    pub type_name: String,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodResult {
    pub method_name: String,
    pub confidence: f32,
    pub proposals: Vec<TypeProposal>,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileAnalysisResult {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub extension: String,
    pub methods: Vec<MethodResult>,
    pub final_type: String,
    pub final_type_description: String,
    pub overall_confidence: f32,
    pub error: Option<String>,
}

// ─── Magic-byte (file-signature) database ───────────────────────────────────

struct MagicEntry {
    ext: &'static str,
    description: &'static str,
    magic: &'static [u8],
    offset: usize,
}

macro_rules! magic {
    ($ext:expr, $desc:expr, $offset:expr, [$($b:expr),+]) => {
        MagicEntry { ext: $ext, description: $desc, magic: &[$($b),+], offset: $offset }
    };
}

static MAGIC_DB: &[MagicEntry] = &[
    // Images
    magic!("JPEG",  "JPEG image",                   0, [0xFF, 0xD8, 0xFF]),
    magic!("PNG",   "PNG image",                    0, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    magic!("GIF87", "GIF image (87a)",              0, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]),
    magic!("GIF89", "GIF image (89a)",              0, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]),
    magic!("BMP",   "Windows Bitmap image",         0, [0x42, 0x4D]),
    magic!("TIFF",  "TIFF image (little-endian)",   0, [0x49, 0x49, 0x2A, 0x00]),
    magic!("TIFF",  "TIFF image (big-endian)",      0, [0x4D, 0x4D, 0x00, 0x2A]),
    magic!("WebP",  "WebP image",                   0, [0x52, 0x49, 0x46, 0x46]),
    magic!("ICO",   "Windows Icon",                 0, [0x00, 0x00, 0x01, 0x00]),
    magic!("PSD",   "Adobe Photoshop document",     0, [0x38, 0x42, 0x50, 0x53]),
    // Audio
    magic!("MP3",   "MP3 audio (ID3 tag)",          0, [0x49, 0x44, 0x33]),
    magic!("MP3",   "MP3 audio (sync frame)",       0, [0xFF, 0xFB]),
    magic!("FLAC",  "FLAC audio",                   0, [0x66, 0x4C, 0x61, 0x43]),
    magic!("OGG",   "OGG container",                0, [0x4F, 0x67, 0x67, 0x53]),
    magic!("WAV",   "WAV audio",                    0, [0x52, 0x49, 0x46, 0x46]),
    magic!("AIFF",  "AIFF audio",                   0, [0x46, 0x4F, 0x52, 0x4D]),
    magic!("MIDI",  "MIDI audio",                   0, [0x4D, 0x54, 0x68, 0x64]),
    // Video / Container
    magic!("FLV",   "Flash Video",                  0, [0x46, 0x4C, 0x56, 0x01]),
    magic!("MKV",   "Matroska video",               0, [0x1A, 0x45, 0xDF, 0xA3]),
    magic!("MP4",   "MP4 / ISOBMFF (ftyp at 4)",   4, [0x66, 0x74, 0x79, 0x70]),
    // Documents
    magic!("PDF",   "PDF document",                 0, [0x25, 0x50, 0x44, 0x46]),
    magic!("PS",    "PostScript document",          0, [0x25, 0x21, 0x50, 0x53]),
    magic!("DjVu",  "DjVu document",                0, [0x41, 0x54, 0x26, 0x54]),
    // Archives / Containers (ZIP-based)
    magic!("ZIP",   "ZIP archive (or ODF/Office Open XML)", 0, [0x50, 0x4B, 0x03, 0x04]),
    magic!("ZIP",   "ZIP archive (empty/spanned)", 0, [0x50, 0x4B, 0x05, 0x06]),
    magic!("RAR",   "RAR archive (v4)",             0, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
    magic!("RAR5",  "RAR archive (v5)",             0, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
    magic!("7Z",    "7-Zip archive",                0, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
    magic!("GZIP",  "GZIP compressed data",         0, [0x1F, 0x8B]),
    magic!("BZ2",   "BZip2 compressed data",        0, [0x42, 0x5A, 0x68]),
    magic!("XZ",    "XZ compressed data",           0, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
    magic!("ZSTD",  "Zstandard compressed data",    0, [0x28, 0xB5, 0x2F, 0xFD]),
    magic!("LZ4",   "LZ4 compressed data",          0, [0x04, 0x22, 0x4D, 0x18]),
    magic!("TAR",   "POSIX TAR archive",            257, [0x75, 0x73, 0x74, 0x61, 0x72]),
    // Executable / Binary
    magic!("ELF",   "ELF executable (Linux/Unix)", 0, [0x7F, 0x45, 0x4C, 0x46]),
    magic!("PE/EXE","Windows PE executable",        0, [0x4D, 0x5A]),
    magic!("MACHO", "Mach-O executable (32-bit)",   0, [0xCE, 0xFA, 0xED, 0xFE]),
    magic!("MACHO", "Mach-O executable (64-bit)",   0, [0xCF, 0xFA, 0xED, 0xFE]),
    magic!("CLASS", "Java class file",              0, [0xCA, 0xFE, 0xBA, 0xBE]),
    magic!("WASM",  "WebAssembly binary",           0, [0x00, 0x61, 0x73, 0x6D]),
    // Database / Data
    magic!("SQLite","SQLite database",              0, [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00]),
    // Font
    magic!("TTF",   "TrueType font",               0, [0x00, 0x01, 0x00, 0x00, 0x00]),
    magic!("WOFF",  "Web Open Font Format",         0, [0x77, 0x4F, 0x46, 0x46]),
    magic!("WOFF2", "Web Open Font Format 2",       0, [0x77, 0x4F, 0x46, 0x32]),
    // Disk image
    magic!("ISO",   "ISO 9660 disk image",          32769, [0x43, 0x44, 0x30, 0x30, 0x31]),
    magic!("VMDK",  "VMDK virtual disk",            0, [0x4B, 0x44, 0x4D, 0x56]),
    // Crypto / Certificates
    magic!("DER",   "DER certificate",             0, [0x30, 0x82]),
    // Text/Script (BOM-prefixed)
    magic!("UTF-8 BOM text",  "UTF-8 text with BOM",  0, [0xEF, 0xBB, 0xBF]),
    magic!("UTF-16 LE text",  "UTF-16 LE text",  0, [0xFF, 0xFE]),
    magic!("UTF-16 BE text",  "UTF-16 BE text",  0, [0xFE, 0xFF]),
];

// ─── Keyword database for string scanning ───────────────────────────────────

struct KeywordEntry {
    keyword: &'static [u8],
    file_type: &'static str,
    description: &'static str,
    weight: f32,
}

macro_rules! kw {
    ($kw:expr, $ft:expr, $desc:expr, $w:expr) => {
        KeywordEntry { keyword: $kw, file_type: $ft, description: $desc, weight: $w }
    };
}

static KEYWORD_DB: &[KeywordEntry] = &[
    kw!(b"<?xml",              "XML",        "XML declaration",                   0.9),
    kw!(b"<!DOCTYPE html",     "HTML",       "HTML DOCTYPE declaration",          0.95),
    kw!(b"<html",              "HTML",       "HTML root element",                 0.85),
    kw!(b"<HTML",              "HTML",       "HTML root element (uppercase)",     0.85),
    kw!(b"<!DOCTYPE",          "HTML/XML",   "DOCTYPE declaration",               0.7),
    kw!(b"%PDF-",              "PDF",        "PDF header marker",                 0.98),
    kw!(b"PK\x03\x04",        "ZIP/ODF",    "ZIP local file header",             0.9),
    kw!(b"#!/usr/bin/env python","Python",   "Python shebang",                    0.95),
    kw!(b"#!/usr/bin/python",  "Python",     "Python shebang (direct)",           0.95),
    kw!(b"# -*- coding:",      "Python",     "Python encoding declaration",       0.85),
    kw!(b"import java.",       "Java",       "Java import statement",             0.85),
    kw!(b"public class ",      "Java",       "Java class declaration",            0.85),
    kw!(b"#!/bin/bash",        "Bash script","Bash shebang",                     0.95),
    kw!(b"#!/bin/sh",          "Shell script","POSIX shell shebang",             0.95),
    kw!(b"<?php",              "PHP",        "PHP opening tag",                   0.95),
    kw!(b"#include <",         "C/C++",      "C/C++ include directive",           0.85),
    kw!(b"fn main()",          "Rust",       "Rust main function",                0.9),
    kw!(b"use std::",          "Rust",       "Rust std use declaration",          0.85),
    kw!(b"[package]",          "TOML",       "TOML package section",              0.85),
    kw!(b"[dependencies]",     "TOML",       "TOML dependencies section",         0.85),
    kw!(b"Creator: Adobe Photoshop","PSD/JPEG","Photoshop creator tag",           0.95),
    kw!(b"Creator:Photoshop",  "PSD/JPEG",   "Photoshop creator tag (compact)",  0.95),
    kw!(b"mimetypeapplication/vnd.oasis.opendocument.drawing","ODG","ODF Drawing MIME type entry", 0.99),
    kw!(b"mimetypeapplication/vnd.oasis.opendocument.text",   "ODT","ODF Text MIME type entry",    0.99),
    kw!(b"mimetypeapplication/vnd.oasis.opendocument.spreadsheet","ODS","ODF Spreadsheet MIME type entry", 0.99),
    kw!(b"mimetypeapplication/vnd.oasis.opendocument.presentation","ODP","ODF Presentation MIME type entry", 0.99),
    kw!(b"word/document.xml",  "DOCX",       "Word document XML part",            0.95),
    kw!(b"xl/workbook.xml",    "XLSX",       "Excel workbook XML part",           0.95),
    kw!(b"ppt/presentation.xml","PPTX",      "PowerPoint presentation XML part",  0.95),
    kw!(b"SQLite format 3",    "SQLite",     "SQLite file format identifier",     0.98),
    kw!(b"fLaC",               "FLAC",       "FLAC stream marker",                0.98),
    kw!(b"ID3",                "MP3",        "MP3 ID3 tag marker",                0.9),
    kw!(b"OggS",               "OGG",        "OGG stream capture pattern",        0.98),
    kw!(b"WEBP",               "WebP",       "WebP format identifier",            0.98),
    kw!(b"ftyp",               "MP4",        "ISO Base Media file-type box",      0.9),
    kw!(b"moov",               "MP4/MOV",    "QuickTime movie container atom",    0.85),
    kw!(b"-----BEGIN ",        "PEM",        "PEM-encoded block header",          0.95),
    kw!(b"-----BEGIN CERTIFICATE-----","X.509 cert","PEM X.509 certificate",      0.98),
    kw!(b"-----BEGIN RSA PRIVATE KEY-----","RSA key","PEM RSA private key",       0.98),
    kw!(b"{\"",                "JSON",       "JSON object opening",               0.65),
    kw!(b"[{\"",               "JSON",       "JSON array of objects opening",     0.7),
];

// ─── Entropy / statistical helpers ──────────────────────────────────────────

fn byte_frequencies(data: &[u8]) -> [f64; 256] {
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let n = data.len() as f64;
    let mut result = [0f64; 256];
    for i in 0..256 { result[i] = freq[i] as f64 / n; }
    result
}

fn shannon_entropy(freq: &[f64; 256]) -> f64 {
    freq.iter().filter(|&&f| f > 0.0).map(|&f| -f * f.log2()).sum()
}

fn printable_ratio(data: &[u8]) -> f64 {
    let printable = data.iter().filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D).count();
    printable as f64 / data.len() as f64
}

fn null_byte_ratio(data: &[u8]) -> f64 {
    let nulls = data.iter().filter(|&&b| b == 0).count();
    nulls as f64 / data.len() as f64
}

fn compute_bigrams(data: &[u8], limit: usize) -> HashMap<(u8, u8), u64> {
    let mut map: HashMap<(u8, u8), u64> = HashMap::new();
    let slice = &data[..data.len().min(limit)];
    for w in slice.windows(2) {
        *map.entry((w[0], w[1])).or_insert(0) += 1;
    }
    map
}

fn pearson_correlation(a: &[f64; 256], b: &[f64; 256]) -> f64 {
    let mean_a: f64 = a.iter().sum::<f64>() / 256.0;
    let mean_b: f64 = b.iter().sum::<f64>() / 256.0;
    let num: f64 = (0..256).map(|i| (a[i] - mean_a) * (b[i] - mean_b)).sum();
    let den_a: f64 = (0..256).map(|i| (a[i] - mean_a).powi(2)).sum::<f64>().sqrt();
    let den_b: f64 = (0..256).map(|i| (b[i] - mean_b).powi(2)).sum::<f64>().sqrt();
    if den_a == 0.0 || den_b == 0.0 { 0.0 } else { num / (den_a * den_b) }
}

// ─── Ideal byte-frequency profiles for cross-correlation ────────────────────

fn profile_ascii_text() -> [f64; 256] {
    let mut p = [0f64; 256];
    let common: &[(u8, f64)] = &[
        (b' ', 0.13), (b'e', 0.06), (b't', 0.05), (b'a', 0.05),
        (b'o', 0.04), (b'n', 0.04), (b'i', 0.04), (b's', 0.04),
        (b'\n', 0.04), (b'\r', 0.01),
    ];
    for &(b, f) in common { p[b as usize] = f; }
    let rest = 0.55 / 86.0;
    for c in 0x21u8..=0x7Eu8 {
        if p[c as usize] == 0.0 { p[c as usize] = rest; }
    }
    p
}

fn profile_compressed() -> [f64; 256] {
    [1.0 / 256.0; 256]
}

fn profile_binary() -> [f64; 256] {
    let mut p = [1.0 / 512.0; 256];
    p[0] = 0.10;
    p
}

// ─── Method 1: File Signatures ───────────────────────────────────────────────

fn analyse_magic(data: &[u8]) -> MethodResult {
    let mut proposals: Vec<TypeProposal> = Vec::new();
    let mut matched_exts: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in MAGIC_DB {
        let start = entry.offset;
        let end = start + entry.magic.len();
        if end > data.len() { continue; }
        if data[start..end] == *entry.magic {
            if matched_exts.insert(entry.ext.to_string()) {
                proposals.push(TypeProposal {
                    type_name: entry.ext.to_string(),
                    confidence: 0.95,
                    description: entry.description.to_string(),
                });
            }
        }
    }

    let reason = if proposals.is_empty() {
        "No known magic byte sequence matched in the file header or at expected offsets.".to_string()
    } else {
        let names: Vec<_> = proposals.iter().map(|p| p.type_name.clone()).collect();
        format!(
            "Matched magic byte sequence(s) at expected byte offset(s): {}. \
             Magic bytes are highly reliable identifiers embedded by the file format specification.",
            names.join(", ")
        )
    };

    let confidence = if proposals.is_empty() { 0.0 } else { 0.95 };

    MethodResult {
        method_name: "File Signatures (Magic Bytes)".to_string(),
        confidence,
        proposals,
        reason,
    }
}

// ─── Method 2: Byte Frequency Analysis ──────────────────────────────────────

fn analyse_byte_frequency(data: &[u8]) -> MethodResult {
    let freq = byte_frequencies(data);
    let entropy = shannon_entropy(&freq);
    let printable = printable_ratio(data);
    let nulls = null_byte_ratio(data);
    let entropy_pct = (entropy / 8.0 * 100.0) as u32;

    let mut proposals = Vec::new();
    let mut reason_parts = Vec::new();

    reason_parts.push(format!(
        "Shannon entropy: {:.2} bits/byte ({entropy_pct}% of maximum 8.0). \
         Printable ASCII ratio: {:.1}%. Null-byte ratio: {:.1}%.",
        entropy, printable * 100.0, nulls * 100.0
    ));

    if entropy > 7.5 {
        proposals.push(TypeProposal {
            type_name: "Compressed / Encrypted data".to_string(),
            confidence: 0.80,
            description: "Nearly uniform byte distribution indicates compressed or encrypted content.".to_string(),
        });
        reason_parts.push("Very high entropy (>7.5 bits) strongly suggests compressed or encrypted data.".to_string());
    } else if printable > 0.90 && entropy < 5.5 {
        proposals.push(TypeProposal {
            type_name: "Plain text (ASCII)".to_string(),
            confidence: 0.75,
            description: "High proportion of printable ASCII with moderate entropy.".to_string(),
        });
        reason_parts.push("High printable ratio (>90%) with moderate entropy is typical of plain text files.".to_string());
    } else if nulls > 0.30 {
        proposals.push(TypeProposal {
            type_name: "Binary / structured binary".to_string(),
            confidence: 0.65,
            description: "Significant null-byte padding common in binary formats.".to_string(),
        });
        reason_parts.push("High null-byte ratio (>30%) is characteristic of structured binary formats.".to_string());
    } else if printable > 0.70 {
        proposals.push(TypeProposal {
            type_name: "Mixed text/binary".to_string(),
            confidence: 0.55,
            description: "Moderate printable content with mixed binary data.".to_string(),
        });
        reason_parts.push("Moderate printable ratio suggests mixed text and binary content.".to_string());
    } else {
        proposals.push(TypeProposal {
            type_name: "Binary data".to_string(),
            confidence: 0.50,
            description: "Byte distribution does not match known plain text patterns.".to_string(),
        });
        reason_parts.push("Byte frequency distribution does not match typical text patterns; likely binary.".to_string());
    }

    let confidence = proposals.first().map(|p| p.confidence).unwrap_or(0.0);

    MethodResult {
        method_name: "Byte Frequency Analysis".to_string(),
        confidence,
        proposals,
        reason: reason_parts.join(" "),
    }
}

// ─── Method 3: Byte Frequency Cross-correlation ──────────────────────────────

fn analyse_cross_correlation(data: &[u8]) -> MethodResult {
    let freq = byte_frequencies(data);
    let corr_text = pearson_correlation(&freq, &profile_ascii_text());
    let corr_comp = pearson_correlation(&freq, &profile_compressed());
    let corr_bin  = pearson_correlation(&freq, &profile_binary());

    let mut scores = vec![
        ("Plain ASCII text",       corr_text, "ASCII text file (e.g. source code, CSV, log)"),
        ("Compressed/Encrypted",   corr_comp, "Compressed or encrypted archive/container"),
        ("Structured binary",      corr_bin,  "Structured binary file (e.g. executable, database)"),
    ];
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    let proposals: Vec<TypeProposal> = scores.iter().take(2).map(|(name, score, desc)| {
        let conf = ((*score + 1.0) / 2.0 * 0.70).max(0.0).min(0.70) as f32;
        TypeProposal {
            type_name: name.to_string(),
            confidence: conf,
            description: desc.to_string(),
        }
    }).collect();

    let top = &scores[0];
    let reason = format!(
        "Pearson correlation of the file's byte-frequency vector against reference profiles — \
         text: {:.3}, compressed: {:.3}, binary: {:.3}. \
         Best match: '{}' (r = {:.3}). Cross-correlation isolates the overall byte-distribution \
         shape, distinguishing structured content from random-looking data.",
        corr_text, corr_comp, corr_bin, top.0, top.1
    );

    let confidence = proposals.first().map(|p| p.confidence).unwrap_or(0.0);

    MethodResult {
        method_name: "Byte Frequency Cross-correlation".to_string(),
        confidence,
        proposals,
        reason,
    }
}

// ─── Method 4: File Header / Trailer Analysis ────────────────────────────────

fn analyse_header_trailer(data: &[u8]) -> MethodResult {
    let mut proposals: Vec<TypeProposal> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    let trailer_db: &[(&[u8], &str, &str)] = &[
        (b"%%EOF",         "PDF",  "PDF end-of-file marker %%EOF"),
        (b"\xff\xd9",      "JPEG", "JPEG end-of-image marker FFD9"),
        (b"IEND\xaeB`\x82","PNG",  "PNG IEND chunk"),
        (b"</html>",       "HTML", "HTML closing tag"),
        (b"</HTML>",       "HTML", "HTML closing tag (uppercase)"),
        (b"</svg>",        "SVG",  "SVG closing tag"),
        (b"</plist>",      "plist","Apple plist closing tag"),
    ];

    let tail_start = data.len().saturating_sub(512);
    let tail = &data[tail_start..];

    for &(marker, ft, desc) in trailer_db {
        if tail.windows(marker.len()).any(|w| w == marker) {
            notes.push(format!("Trailer: {} ({})", desc, ft));
            proposals.push(TypeProposal {
                type_name: ft.to_string(),
                confidence: 0.85,
                description: format!("Recognised end-of-file marker: {}", desc),
            });
        }
    }

    let internal_db: &[(&[u8], &str, &str)] = &[
        (b"mimetypeapplication/vnd.oasis", "ODF", "OpenDocument Format MIME type entry near start"),
        (b"word/document.xml",  "DOCX", "Word document internal path in ZIP"),
        (b"xl/workbook.xml",    "XLSX", "Excel workbook internal path in ZIP"),
        (b"ppt/presentation.xml","PPTX","PowerPoint internal path in ZIP"),
    ];

    let search_window = data.len().min(8192);
    for &(marker, ft, desc) in internal_db {
        if data[..search_window].windows(marker.len()).any(|w| w == marker) {
            notes.push(format!("Internal marker: {} ({})", desc, ft));
            proposals.push(TypeProposal {
                type_name: ft.to_string(),
                confidence: 0.88,
                description: format!("Internal structure marker detected: {}", desc),
            });
        }
    }

    let mut seen = std::collections::HashSet::new();
    proposals.retain(|p| seen.insert(p.type_name.clone()));

    let confidence = proposals.first().map(|p| p.confidence).unwrap_or(0.0);
    let reason = if notes.is_empty() {
        "No recognised end-of-file trailers or internal non-contiguous structural markers were identified.".to_string()
    } else {
        notes.join("; ")
    };

    MethodResult {
        method_name: "File Header / Trailer Analysis".to_string(),
        confidence,
        proposals,
        reason,
    }
}

// ─── Method 5: N-gram (Bigram) Analysis ──────────────────────────────────────

fn analyse_ngram(data: &[u8]) -> MethodResult {
    let limit = data.len().min(65536);
    let bigrams = compute_bigrams(data, limit);
    let total: u64 = bigrams.values().sum();

    if total == 0 {
        return MethodResult {
            method_name: "N-gram Analysis (Bigrams)".to_string(),
            confidence: 0.0,
            proposals: vec![],
            reason: "File is too small or empty for n-gram analysis.".to_string(),
        };
    }

    let ascii_pair: u64 = bigrams.iter()
        .filter(|&(&(a, b), _)| a >= 0x20 && a <= 0x7E && b >= 0x20 && b <= 0x7E)
        .map(|(_, &v)| v).sum();
    let null_pair: u64 = bigrams.get(&(0, 0)).copied().unwrap_or(0);
    let high_byte_pair: u64 = bigrams.iter()
        .filter(|&(&(a, b), _)| a > 0x7F || b > 0x7F)
        .map(|(_, &v)| v).sum();

    let ascii_ratio = ascii_pair as f64 / total as f64;
    let null_ratio  = null_pair  as f64 / total as f64;
    let high_ratio  = high_byte_pair as f64 / total as f64;

    let english_bigrams: &[(u8, u8)] = &[
        (b't', b'h'), (b'h', b'e'), (b'i', b'n'), (b'e', b'r'),
        (b'a', b'n'), (b'r', b'e'), (b'o', b'n'), (b'e', b'n'),
        (b'a', b't'), (b'e', b's'), (b's', b't'), (b'e', b'd'),
    ];
    let english_count: u64 = english_bigrams.iter()
        .map(|&(a, b)| bigrams.get(&(a, b)).copied().unwrap_or(0)
                     + bigrams.get(&(a.to_ascii_uppercase(), b)).copied().unwrap_or(0))
        .sum();
    let english_ratio = english_count as f64 / total as f64;

    let mut proposals = Vec::new();
    let mut notes = Vec::new();

    notes.push(format!(
        "Analysed {} bigrams (first {} bytes). ASCII-pair: {:.1}%, null-pair: {:.1}%, \
         high-byte-pair: {:.1}%, English-letter-bigram: {:.1}%.",
        total, limit,
        ascii_ratio * 100.0, null_ratio * 100.0,
        high_ratio * 100.0, english_ratio * 100.0,
    ));

    if english_ratio > 0.04 && ascii_ratio > 0.60 {
        proposals.push(TypeProposal {
            type_name: "Natural-language text".to_string(),
            confidence: 0.72,
            description: "High frequency of common English letter sequences.".to_string(),
        });
        notes.push("Elevated frequency of common English bigrams (th, he, in, er…) strongly suggests natural-language prose.".to_string());
    } else if ascii_ratio > 0.70 {
        proposals.push(TypeProposal {
            type_name: "ASCII text / source code".to_string(),
            confidence: 0.65,
            description: "Predominantly ASCII byte pairs without strong natural-language pattern.".to_string(),
        });
        notes.push("High ASCII bigram ratio suggests text or source code.".to_string());
    } else if null_ratio > 0.10 {
        proposals.push(TypeProposal {
            type_name: "Structured binary (null-padded)".to_string(),
            confidence: 0.60,
            description: "Significant consecutive null bytes indicate alignment padding in binary formats.".to_string(),
        });
        notes.push("Significant null-pair bigrams indicate binary structure with alignment/padding.".to_string());
    } else if high_ratio > 0.50 {
        proposals.push(TypeProposal {
            type_name: "Compressed / high-entropy binary".to_string(),
            confidence: 0.62,
            description: "Many high-byte pairs indicate dense binary or compressed content.".to_string(),
        });
        notes.push("Predominance of high-byte bigrams suggests compressed or encrypted data.".to_string());
    } else {
        proposals.push(TypeProposal {
            type_name: "Binary data".to_string(),
            confidence: 0.45,
            description: "Mixed byte pair distribution without a distinguishing pattern.".to_string(),
        });
    }

    let confidence = proposals.first().map(|p| p.confidence).unwrap_or(0.0);

    MethodResult {
        method_name: "N-gram Analysis (Bigrams)".to_string(),
        confidence,
        proposals,
        reason: notes.join(" "),
    }
}

// ─── Method 6: Strings / Keyword Analysis ────────────────────────────────────

fn analyse_strings_keywords(data: &[u8]) -> MethodResult {
    let mut proposals: Vec<(String, f32, String)> = Vec::new();
    let mut matches: Vec<String> = Vec::new();

    for entry in KEYWORD_DB {
        if data.windows(entry.keyword.len()).any(|w| w == entry.keyword) {
            if let Some(existing) = proposals.iter_mut().find(|(t, _, _)| t == entry.file_type) {
                existing.1 = (existing.1 + entry.weight * 0.05).min(0.97);
            } else {
                proposals.push((
                    entry.file_type.to_string(),
                    entry.weight.min(0.96),
                    entry.description.to_string(),
                ));
            }
            matches.push(format!("'{}' → {}", entry.description, entry.file_type));
        }
    }

    proposals.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    let type_proposals: Vec<TypeProposal> = proposals.iter().take(5).map(|(t, c, d)| TypeProposal {
        type_name: t.clone(),
        confidence: *c,
        description: d.clone(),
    }).collect();

    let confidence = type_proposals.first().map(|p| p.confidence).unwrap_or(0.0);

    let reason = if matches.is_empty() {
        "No recognisable file-type strings or application-specific keywords were found.".to_string()
    } else {
        format!("Found {} keyword match(es): {}.", matches.len(), matches.join("; "))
    };

    MethodResult {
        method_name: "Strings and Keyword Analysis".to_string(),
        confidence,
        proposals: type_proposals,
        reason,
    }
}

// ─── Result aggregation ──────────────────────────────────────────────────────

fn aggregate_results(methods: &[MethodResult], extension: &str) -> (String, String, f32) {
    let weights: &[(&str, f32)] = &[
        ("File Signatures (Magic Bytes)",      3.0),
        ("Strings and Keyword Analysis",       2.5),
        ("File Header / Trailer Analysis",     2.0),
        ("Byte Frequency Analysis",            1.0),
        ("Byte Frequency Cross-correlation",   0.8),
        ("N-gram Analysis (Bigrams)",          0.7),
    ];

    let mut scores: HashMap<String, (f32, f32, String)> = HashMap::new();

    for method in methods {
        let w = weights.iter().find(|(n, _)| *n == method.method_name).map(|(_, w)| *w).unwrap_or(1.0);
        for proposal in &method.proposals {
            let norm_conf = proposal.confidence * w;
            let entry = scores.entry(proposal.type_name.clone())
                .or_insert((0.0, 0.0, proposal.description.clone()));
            entry.0 += norm_conf;
            entry.1 += w;
        }
    }

    if scores.is_empty() {
        if !extension.is_empty() {
            return (
                format!("{} (extension only)", extension.to_uppercase()),
                format!("File type identified solely by the file extension '.{}'. No binary analysis produced a match.", extension),
                0.20,
            );
        }
        return ("Unknown".to_string(), "No analysis method produced a file type match.".to_string(), 0.0);
    }

    let mut ranked: Vec<(String, f32, String)> = scores.into_iter()
        .map(|(k, (score, total_w, desc))| (k, if total_w > 0.0 { score / total_w } else { 0.0 }, desc))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    let (best_type, best_conf, best_desc) = &ranked[0];

    let ext_matches = !extension.is_empty() &&
        best_type.to_lowercase().contains(&extension.to_lowercase());
    let final_conf = (best_conf + if ext_matches { 0.03 } else { 0.0 }).min(0.99);

    let description = format!(
        "{}  Identified as '{}' with {:.0}% overall certainty across all six analysis methods.",
        best_desc, best_type, final_conf * 100.0
    );

    (best_type.clone(), description, final_conf)
}

// ─── Single-file analysis entry point ────────────────────────────────────────

fn analyse_single_file(path: &str) -> FileAnalysisResult {
    let p = Path::new(path);
    let file_name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let extension = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();

    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(e) => return FileAnalysisResult {
            file_path: path.to_string(), file_name, file_size: 0,
            extension: extension.to_string(), methods: vec![],
            final_type: "Error".to_string(),
            final_type_description: format!("Could not read file metadata: {}", e),
            overall_confidence: 0.0, error: Some(e.to_string()),
        },
    };

    let file_size = meta.len();

    let data = match fs::read(p) {
        Ok(d) => d,
        Err(e) => return FileAnalysisResult {
            file_path: path.to_string(), file_name, file_size,
            extension: extension.to_string(), methods: vec![],
            final_type: "Error".to_string(),
            final_type_description: format!("Could not read file: {}", e),
            overall_confidence: 0.0, error: Some(e.to_string()),
        },
    };

    // Limit to 512 KiB for performance
    let analysis_data: &[u8] = if data.len() > 524288 { &data[..524288] } else { &data };

    if analysis_data.is_empty() {
        return FileAnalysisResult {
            file_path: path.to_string(), file_name, file_size,
            extension: extension.to_string(), methods: vec![],
            final_type: "Empty file".to_string(),
            final_type_description: "The file is empty (0 bytes).".to_string(),
            overall_confidence: 1.0, error: None,
        };
    }

    let methods = vec![
        analyse_magic(analysis_data),
        analyse_byte_frequency(analysis_data),
        analyse_cross_correlation(analysis_data),
        analyse_header_trailer(analysis_data),
        analyse_ngram(analysis_data),
        analyse_strings_keywords(analysis_data),
    ];

    let (final_type, final_type_description, overall_confidence) =
        aggregate_results(&methods, &extension);

    FileAnalysisResult {
        file_path: path.to_string(), file_name, file_size,
        extension: extension.to_string(), methods, final_type,
        final_type_description, overall_confidence, error: None,
    }
}

// ─── Tauri commands ──────────────────────────────────────────────────────────

#[tauri::command]
async fn analyse_files(paths: Vec<String>) -> Vec<FileAnalysisResult> {
    paths.iter().map(|p| analyse_single_file(p)).collect()
}

#[tauri::command]
async fn pick_files() -> Result<Vec<String>, String> {
    let handles = rfd::AsyncFileDialog::new()
        .set_title("Select file(s) to analyse")
        .pick_files()
        .await;
    match handles {
        Some(files) => Ok(files.iter().map(|h| h.path().to_string_lossy().to_string()).collect()),
        None => Ok(vec![]),
    }
}

#[tauri::command]
async fn pick_folder() -> Result<Vec<String>, String> {
    let handle = rfd::AsyncFileDialog::new()
        .set_title("Select folder to analyse")
        .pick_folder()
        .await;
    match handle {
        Some(folder) => {
            let paths: Vec<String> = WalkDir::new(folder.path())
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .map(|e| e.path().to_string_lossy().to_string())
                .collect();
            Ok(paths)
        }
        None => Ok(vec![]),
    }
}

#[tauri::command]
async fn pick_save_path() -> Result<Option<String>, String> {
    let handle = rfd::AsyncFileDialog::new()
        .set_title("Save analysis results")
        .add_filter("Text file", &["txt"])
        .set_file_name("file_analysis_results.txt")
        .save_file()
        .await;
    Ok(handle.map(|h| h.path().to_string_lossy().to_string()))
}

#[tauri::command]
fn save_results(path: String, content: String) -> Result<(), String> {
    fs::write(&path, content.as_bytes()).map_err(|e| e.to_string())
}

#[tauri::command]
fn current_timestamps() -> (String, String) {
    use chrono::{Local, Utc};
    let local = Local::now();
    let utc   = Utc::now();
    let local_str = format!("{} {}", local.format("%Y-%m-%dT%H:%M:%S%:z"), local.format("%Z"));
    let utc_str   = format!("{} UTC", utc.format("%Y-%m-%dT%H:%M:%SZ"));
    (local_str, utc_str)
}

// ─── App entry point ─────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            analyse_files,
            pick_files,
            pick_folder,
            pick_save_path,
            save_results,
            current_timestamps,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
