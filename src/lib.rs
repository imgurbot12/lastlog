/*!

 A simple user crate designed to read `/var/log/lastlog`
 for retrieving last-login records on linux systems

 ---

 The basic usage looks like:
 ```rust,no_run
 use lastlog::{search_uid, search_username};

 fn main() {
    let result1 = search_uid(1000);
    let result2 = search_username("foo");
 }
 ```

 NOTE: this functionality will ONLY work on **UNIX** operating
 systems that support the `/var/log/lastlog` database

*/
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::slice;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cached::proc_macro::cached;

/* Variables */

static PASSWD: &str = "/etc/passwd";
static LASTLOG: &str = "/var/log/lastlog";
static ST_SIZE: usize = std::mem::size_of::<RStruct>();

/* Types */

#[derive(Debug)]
pub enum LoginTime {
    NeverLoggedIn,
    LoggedIn(SystemTime),
}

#[derive(Debug)]
pub struct Record {
    pub uid: u32,
    pub tty: String,
    pub last_login: LoginTime,
}

#[derive(Debug, Clone)]
struct User {
    uid: u32,
    name: String,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct RStruct(u32, [u8; 32], [u8; 256]);

/* Functions */

#[inline]
fn unix_timestamp(ts: u32) -> LoginTime {
    if ts > 0 {
        return LoginTime::LoggedIn(UNIX_EPOCH + Duration::from_secs(ts as u64));
    }
    LoginTime::NeverLoggedIn
}

// map rstruct object into public record object
fn map_record(uid: u32, st: RStruct) -> io::Result<Record> {
    let tty = std::str::from_utf8(&st.1).map_err(|_| io::ErrorKind::InvalidData)?;
    Ok(Record {
        uid,
        tty: tty.trim_matches('\0').to_owned(),
        last_login: unix_timestamp(st.0),
    })
}

// read serialized C struct into object
fn read_struct<T, R: Read>(mut read: R) -> io::Result<T> {
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

// read lastlog for a given user uid
fn read_lastlog(f: &mut File, uid: usize) -> io::Result<RStruct> {
    // seek lastlog db based on uid and read RStruct object size
    let mut buffer = vec![0; ST_SIZE];
    f.seek(SeekFrom::Start((uid * ST_SIZE) as u64))?;
    f.read_exact(&mut buffer)?;
    // parse value into rstruct bytes
    read_struct::<RStruct, _>(&buffer[..])
}

// parse /etc/passwd for users and uids on system
#[cached]
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

/// Generate a manifest of logins for all linux user accounts
///
/// This will attempt to read and iterate every user account
/// found in `/etc/passwd` and retrieve the last login information
/// from `/var/log/lastlog`
///
/// # Examples
///
/// Basic Usage:
///
/// ```
/// let accounts = iter_accounts().unwrap()
/// for account in accounts.iter() {
///     println!("{:?}", account);
/// }
/// ```
pub fn iter_accounts() -> io::Result<HashMap<String, Record>> {
    let mut f = File::open(&LASTLOG)?;
    let mut log = HashMap::new();
    for user in read_passwd().into_iter() {
        let rstruct = read_lastlog(&mut f, user.uid as usize)?;
        let record = map_record(user.uid, rstruct)?;
        log.insert(user.name, record);
    }
    Ok(log)
}

/// Get the login record for a single valid linux user-id
///
/// This avoids iterating `/etc/passwd` altogether and simply
/// does a `/var/log/lastlog` database lookup to retrieve the
/// last-login information
///
/// # Examples
///
/// Basic Usage:
///
/// ```
/// let record = search_uid(1000);
/// ```
pub fn search_uid(uid: u32) -> io::Result<Record> {
    let mut f = File::open(&LASTLOG)?;
    let rstruct = read_lastlog(&mut f, uid as usize)?;
    map_record(uid, rstruct)
}

/// Find the username's associated UID and collect the linked login-record
///
/// This iterates `/etc/passwd` to find the associated user-id and will
/// raise an error if the account username does not exist. Then it does
/// a simple database lookup to `/var/log/lastlog` to find the last login
///
/// # Examples
///
/// Basic Usage:
///
/// ```
/// let record = search_username("foo");
/// ```
pub fn search_username(name: &str) -> io::Result<Record> {
    let users = read_passwd().into_iter();
    let filtered: Vec<_> = users.filter(|u| u.name == name).collect();
    if filtered.len() != 1 {
        let err = io::Error::new(io::ErrorKind::NotFound, "No such user");
        return Err(err);
    }
    search_uid(filtered[0].uid)
}
