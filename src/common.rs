/*
 * Common Utilities used for Lastlog and Utmp Reading
 */
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Result};
use std::slice;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "cached")]
use cached::proc_macro::cached;

/* Variables */

static PASSWD: &str = "/etc/passwd";
static USER_ENV: &str = "USER";

/* Types */

#[derive(Debug, Clone)]
struct User {
    pub uid: u32,
    pub name: String,
}

/// Utmp RecordType
/// (https://man7.org/linux/man-pages/man5/utmp.5.html)
#[derive(Debug, Clone, PartialEq)]
pub enum RecordType {
    Empty,
    RunLvl,
    BootTime,
    NewTime,
    OldTime,
    InitProc,
    LoginProc,
    User,
    DeadProc,
    Accounting,
}

impl TryFrom<i32> for RecordType {
    type Error = String;
    fn try_from(value: i32) -> std::prelude::v1::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Empty),
            1 => Ok(Self::RunLvl),
            2 => Ok(Self::BootTime),
            3 => Ok(Self::NewTime),
            4 => Ok(Self::OldTime),
            5 => Ok(Self::InitProc),
            6 => Ok(Self::LoginProc),
            7 => Ok(Self::User),
            8 => Ok(Self::DeadProc),
            9 => Ok(Self::Accounting),
            _ => Err(format!("Invalid RecordType: {value:?}")),
        }
    }
}

/// Simple Enum for declaring last login-time
#[derive(Debug, Clone)]
pub enum LoginTime {
    Never,
    Last(SystemTime),
}

impl From<SystemTime> for LoginTime {
    fn from(v: SystemTime) -> Self {
        LoginTime::Last(v)
    }
}

impl From<Option<SystemTime>> for LoginTime {
    fn from(v: Option<SystemTime>) -> Self {
        match v {
            None => LoginTime::Never,
            Some(time) => LoginTime::from(time),
        }
    }
}

impl Into<Option<SystemTime>> for LoginTime {
    fn into(self) -> Option<SystemTime> {
        match self {
            LoginTime::Never => None,
            LoginTime::Last(time) => Some(time),
        }
    }
}

/// Single Database Record instance for a given user's latest-login information
#[derive(Debug)]
pub struct Record {
    pub rtype: RecordType,
    pub uid: Option<u32>,
    pub name: String,
    pub tty: String,
    pub last_login: LoginTime,
}

/// Public Trait for specific linux database search implementations
///
/// This enables lower level control and access to various resources
/// on the linux filesystem while also enabling the generalized functions
/// to find the best option amongst the existing implementations
pub trait LoginDB {
    fn is_valid(&self, f: &mut File) -> bool;
    fn primary_file(&self) -> Result<&'static str>;
    fn iter_accounts(&self, fname: &str) -> Result<Vec<Record>>;
    fn search_uid(&self, uid: u32, fname: &str) -> Result<Record>;
    fn search_username(&self, username: &str, fname: &str) -> Result<Record>;
}

/* Functions */

// convert unix-timestamp to system-time object (when applicable)
#[inline]
pub fn unix_timestamp(ts: u32) -> LoginTime {
    if ts > 0 {
        return LoginTime::Last(UNIX_EPOCH + Duration::from_secs(ts as u64));
    }
    LoginTime::Never
}

// read serialized C struct into object
pub fn read_struct<T, R: Read>(mut read: R) -> Result<T> {
    let num_bytes = ::std::mem::size_of::<T>();
    unsafe {
        let mut s = ::std::mem::zeroed();
        let buffer = slice::from_raw_parts_mut(&mut s as *mut T as *mut u8, num_bytes);
        match read.read_exact(buffer) {
            Ok(()) => Ok(s),
            Err(e) => {
                ::std::mem::forget(s);
                Err(e)
            }
        }
    }
}

// generate empty user record for the given uid/name
pub fn new_record(uid: u32, name: String) -> Record {
    Record {
        rtype: RecordType::User,
        uid: Some(uid),
        name,
        tty: "".to_owned(),
        last_login: LoginTime::Never,
    }
}

// parse /etc/passwd for users and uids on system
fn read_passwd() -> Vec<User> {
    let f = File::open(&PASSWD).expect("unable to read /etc/passwd");
    let mut users = vec![];
    for rline in BufReader::new(f).lines() {
        let Ok(line) = rline else { continue };
        if line.trim().len() == 0 {
            continue;
        };
        let mut temp = line.splitn(4, ':');
        let name = temp.next().expect("Invalid /etc/passwd Entry");
        temp.next();
        let raw_uid = temp.next().expect("Invalid /etc/passwd UID");
        users.push(User {
            name: name.to_owned(),
            uid: raw_uid.parse::<u32>().expect("Invalid user UID"),
        });
    }
    users
}

#[cfg(not(feature = "cached"))]
pub fn read_passwd_nmap() -> HashMap<String, u32> {
    read_passwd().into_iter().map(|r| (r.name, r.uid)).collect()
}

#[cfg(not(feature = "cached"))]
pub fn read_passwd_idmap() -> HashMap<u32, String> {
    read_passwd().into_iter().map(|r| (r.uid, r.name)).collect()
}

#[cfg(feature = "cached")]
#[cached]
pub fn read_passwd_idmap() -> HashMap<u32, String> {
    read_passwd().into_iter().map(|r| (r.uid, r.name)).collect()
}

#[cfg(feature = "cached")]
#[cached]
pub fn read_passwd_nmap() -> HashMap<String, u32> {
    read_passwd().into_iter().map(|r| (r.name, r.uid)).collect()
}

// retrieve best guess for user id from system
pub fn guess_uid() -> u32 {
    let mut uid = 0;
    if let Ok(user) = env::var(USER_ENV) {
        let users = read_passwd_nmap();
        uid = *users.get(&user).unwrap_or(&uid);
    }
    uid
}
