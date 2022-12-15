/*
 *  Linux `/var/log/lastlog` db reader
 */
use std::fs::{metadata, File};
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};

use super::common::*;

/* Variables */

static ST_SIZE: usize = std::mem::size_of::<RStruct>();

/* Type */

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct RStruct(u32, [u8; 32], [u8; 256]);

/* Function */

// map rstruct object into public record object
fn map_record(name: &str, uid: u32, st: RStruct) -> Result<Record> {
    let tty = std::str::from_utf8(&st.1).map_err(|_| ErrorKind::InvalidData)?;
    Ok(Record {
        uid,
        name: name.to_owned(),
        tty: tty.trim_matches('\0').to_owned(),
        last_login: unix_timestamp(st.0),
    })
}

// read lastlog for a given user uid and map to record object
fn read_lastlog(f: &mut File, name: &str, uid: usize) -> Result<Record> {
    // seek lastlog db based on uid and read RStruct object size
    let mut buffer = vec![0; ST_SIZE];
    f.seek(SeekFrom::Start((uid * ST_SIZE) as u64))?;
    f.read_exact(&mut buffer)?;
    // parse value into rstruct bytes
    let st = read_struct::<RStruct, _>(&buffer[..])?;
    map_record(name, uid as u32, st)
}

/* Implementation */

/// Lastlog Database Reader Implementation
///
/// This module allows for reading the [lastlog](https://linux.die.net/man/8/lastlog)
/// database format.
///
/// # Examples
///
/// Basic Usage:
/// ```
/// let llog   = LastLog {};
/// let record = llog.search_uid(1000, "/var/log/lastlog");
/// ```
pub struct LastLog {}

impl Module for LastLog {
    fn is_valid(&self, f: &mut File) -> bool {
        let uid = guess_uid();
        read_lastlog(f, "", uid as usize).is_ok()
    }

    fn primary_file(&self) -> Result<&'static str> {
        for fpath in vec!["/var/log/lastlog"].iter() {
            let Ok(meta) = metadata(fpath) else { continue };
            if meta.is_file() {
                return Ok(fpath);
            }
        }
        Err(Error::new(
            ErrorKind::NotFound,
            "cannot find valid lastlog path",
        ))
    }

    fn iter_accounts(&self, fname: &str) -> Result<Vec<Record>> {
        let mut records = vec![];
        let mut f = File::open(fname)?;
        // sort map of user accounts by user-id to ensure nobacktracking on seek action
        let mut users: Vec<_> = read_passwd_idmap().into_iter().collect();
        users.sort_by_key(|(uid, _)| *uid);
        for (uid, name) in users.into_iter() {
            let record = read_lastlog(&mut f, &name, uid as usize)?;
            records.push(record);
        }
        Ok(records)
    }

    fn search_uid(&self, uid: u32, fname: &str) -> Result<Record> {
        let users = read_passwd_idmap();
        let name = users
            .get(&uid)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "no such user"))?;
        let mut f = File::open(fname)?;
        read_lastlog(&mut f, name, uid as usize)
    }

    fn search_username(&self, username: &str, fname: &str) -> Result<Record> {
        let users = read_passwd_nmap();
        let uid = users
            .get(username)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "no such user"))?;
        let mut f = File::open(fname)?;
        read_lastlog(&mut f, username, *uid as usize)
    }
}
