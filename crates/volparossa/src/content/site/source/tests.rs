// SPDX-License-Identifier: GPL-3.0-only
use std::{fs, os::unix::fs::symlink, time::SystemTime};

use volparossa_content::site::SiteBundle;

use super::*;

#[test]
fn rejects_a_replaced_file_or_a_parent_replaced_by_a_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let index = directory.path().join("index.html");
    fs::write(&index, b"selected").unwrap();
    let root = File::open(directory.path()).unwrap();
    let assets = collect(&root).unwrap();
    fs::rename(&index, directory.path().join(".original")).unwrap();
    fs::write(&index, b"replaced").unwrap();
    assert!(SiteBundle::write_to(assets, &mut io::sink()).is_err());

    let styles = directory.path().join("styles");
    fs::create_dir(&styles).unwrap();
    fs::write(styles.join("site.css"), b"body{}").unwrap();
    let root = File::open(directory.path()).unwrap();
    let assets = collect(&root).unwrap();
    assert_eq!(assets.len(), 2);
    let moved = directory.path().join(".saved");
    fs::rename(&styles, &moved).unwrap();
    symlink(&moved, &styles).unwrap();
    assert!(SiteBundle::write_to(assets, &mut io::sink()).is_err());
}

#[test]
fn checks_the_open_file_again_after_its_bytes_have_been_read() {
    let directory = tempfile::tempdir().unwrap();
    let index = directory.path().join("index.html");
    fs::write(&index, b"selected").unwrap();
    let root = File::open(directory.path()).unwrap();
    let mut reader = collect(&root).unwrap().pop().unwrap().reader;
    let mut first = [0; 1];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"s");
    fs::write(&index, b"modified").unwrap();
    // Force a distinct timestamp even on filesystems with coarse timestamp resolution.
    File::open(&index)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH)
        .unwrap();
    let mut rest = Vec::new();
    assert_eq!(
        reader.read_to_end(&mut rest).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn continues_under_the_original_root_when_its_path_is_replaced() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("site");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("index.html"), b"selected").unwrap();
    let root = File::open(&directory).unwrap();
    let assets = collect(&root).unwrap();
    fs::rename(&directory, parent.path().join("previous")).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("index.html"), b"replaced").unwrap();
    let mut encoded = Vec::new();
    SiteBundle::write_to(assets, &mut encoded).unwrap();
    let bundle = SiteBundle::decode(encoded).unwrap();
    assert_eq!(bundle.asset("/index.html").unwrap().bytes, b"selected");
}
