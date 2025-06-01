/*
 * Linux utmp db reader
 */
use std::collections::HashMap;
use std::fs::{metadata, File};
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};

use super::common::*;

/* Variables */

static ST_SIZE: usize = std::mem::size_of::<RStruct>();

/* Type */

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct RStruct {
    //NOTE: rtype size by all recorded documentation should i16
    // yet for some reason it's actually an i32 and i have no idea why
    rtype: i32,
    pid: i32,
    line: [u8; 32],
    id: [u8; 4],
    user: [u8; 32],
    host: [u8; 256],
    exit: [i16; 2],
    session: i32,
    sec: i32,
    usec: i32,
    addr: [i32; 4],
    unused: [u8; 20],
}

/* Functions */

#[inline]
fn stringify<'a>(name: &str, string: &'a [u8]) -> Result<&'a str> {
    Ok(std::str::from_utf8(string)
        .map_err(|_| Error::new(ErrorKind::InvalidData, format!("invalid {name}")))?
        .trim_matches('\0'))
}

// map rstruct object into public record object
fn map_record(umap: &HashMap<String, u32>, st: RStruct) -> Result<Record> {
    let tty = stringify("tty", &st.line)?;
    let name = stringify("username", &st.user)?;
    let rtype =
        RecordType::try_from(st.rtype).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    Ok(Record {
        rtype,
        uid: umap.get(name).map(|uid| *uid),
        name: name.to_owned(),
        tty: tty.trim_matches('\0').to_owned(),
        last_login: unix_timestamp(st.sec as u32),
    })
}

// replace hashmap entry if login was newer than current record
fn set_latest(all: &mut HashMap<String, Record>, new: Record) {
    if let Some(rec) = all.get(&new.name) {
        if let LoginTime::Last(old) = rec.last_login {
            if let LoginTime::Last(new) = new.last_login {
                if old > new {
                    return;
                }
            }
        }
    }
    all.insert(new.name.to_owned(), new);
}

// read single entry from utmp file
#[inline]
fn read_utmp(f: &mut File, buf: &mut Vec<u8>) -> Result<RStruct> {
    f.read(buf)?;
    let st = read_struct::<RStruct, _>(&buf[..])?;
    if st.rtype < 0 || st.rtype > 10 || st.sec == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "read invalid struct"));
    }
    Ok(st)
}

// dynamic read-until manager for reading utmp/wtmp/btmp file object
fn read_until<F>(umap: &HashMap<String, u32>, fname: &str, until: F) -> Result<Vec<Record>>
where
    F: Fn(&Record) -> bool,
{
    let mut f = File::open(fname)?;
    let mut seek = f.seek(SeekFrom::End(0))?;
    let mut buffer = vec![0; ST_SIZE];
    let mut records = HashMap::new();
    while seek > 0 {
        // read raw struct from buffer and update seek position
        seek -= ST_SIZE as u64;
        f.seek(SeekFrom::Start(seek))?;
        let st = read_utmp(&mut f, &mut buffer)?;
        // convert into standard record object
        let rec = map_record(&umap, st)?;
        if until(&rec) {
            set_latest(&mut records, rec);
            break;
        }
        set_latest(&mut records, rec);
    }
    // assign empty records for accounts that have never logged-in
    for (user, uid) in umap.iter() {
        if !records.contains_key(user) {
            records.insert(user.to_owned(), new_record(*uid, user.to_owned()));
        }
    }
    Ok(records.into_values().collect())
}

/* Implementation */

/// UTMP/WTMP Database Reader Implementation
///
/// This module allows for reading the [utmp](https://linux.die.net/man/5/utmp)
/// database format.
///
/// # Examples
///
/// Basic Usage:
/// ```
/// use lastlog::LoginDB;
///
/// let utmp   = lastlog::Utmp {};
/// let record = utmp.search_uid(1000, "/var/log/wtmp");
/// let all_records = utmp.read_all("/var/run/utmp");
/// ```
pub struct Utmp {}

impl Utmp {
    /// Read all records contained within a Utmp file
    ///
    /// This includes process-entries / system-accounts / reboots / etc...
    ///
    /// # Examples
    ///
    /// Basic Usage:
    ///
    /// ```
    /// use lastlog::LoginDB;
    ///
    /// let utmp = lastlog::Utmp {};
    /// let records = utmp.read_all("/var/run/utmp");
    /// ```
    pub fn read_all(&self, fname: &str) -> Result<Vec<Record>> {
        let users = read_passwd_nmap();
        read_until(&users, fname, |_| false)
    }
}

impl LoginDB for Utmp {
    fn is_valid(&self, f: &mut File) -> bool {
        let mut buffer = vec![0; ST_SIZE];
        read_utmp(f, &mut buffer).is_ok()
    }

    fn primary_file(&self) -> Result<&'static str> {
        for fpath in vec!["/var/run/utmp", "/var/log/utmp", "/var/log/wtmp"].iter() {
            let Ok(meta) = metadata(fpath) else { continue };
            if meta.is_file() {
                return Ok(fpath);
            }
        }
        Err(Error::new(
            ErrorKind::NotFound,
            "cannot find valid utmp/wtmp path",
        ))
    }

    // iterate all accounts in /etc/passwd and generate relevant records
    fn iter_accounts(&self, fname: &str) -> Result<Vec<Record>> {
        let mut results = HashMap::new();
        let records = self.read_all(fname)?;
        for rec in records
            .into_iter()
            .filter(|r| r.rtype == RecordType::User)
            .filter(|r| r.uid.is_some())
        {
            results.insert(rec.uid, rec);
        }
        Ok(results.into_values().collect())
    }

    // search for latest login for a given uid
    fn search_uid(&self, uid: u32, fname: &str) -> Result<Record> {
        let users = read_passwd_nmap();
        let records = read_until(&users, fname, |r| r.uid == Some(uid))?;
        for record in records.into_iter() {
            if record.uid == Some(uid) {
                return Ok(record);
            }
        }
        Err(Error::new(ErrorKind::InvalidInput, "no such user"))
    }

    // search for latest login for a given username
    fn search_username(&self, username: &str, fname: &str) -> Result<Record> {
        let users = read_passwd_nmap();
        let records = read_until(&users, fname, |r| r.name == username)?;
        for record in records.into_iter() {
            if record.name == username {
                return Ok(record);
            }
        }
        Err(Error::new(ErrorKind::InvalidInput, "no such user"))
    }
}
