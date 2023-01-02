/*!

 Simple crate for retrieving latest last-login records on a UNIX system
 ---

 The basic usage looks like:
 ```rust,no_run
 use lastlog::{search_uid, search_username};

 fn main() {
    let result1 = search_uid(1000);
    let result2 = search_username("foo");
 }
 ```

 NOTE: this functionality is only designed to work with UNIX systems
 that support either utmp/wtmp or lastlog database types.

*/
use std::env;
use std::fs::File;
use std::io::{Error, ErrorKind, Result};

use libc::getuid;

mod common;
mod lastlog;
mod utmp;

pub use common::{LoginTime, Module, Record};
pub use lastlog::LastLog;
pub use utmp::Utmp;

/* Varaibles */

static ENV: &str = "LASTLOG";

/* Functions */

#[inline]
fn modules() -> Vec<Box<dyn Module>> {
    vec![Box::new(utmp::Utmp {}), Box::new(lastlog::LastLog {})]
}

// find best suited module to retrieve lastlog data
fn get_module() -> Result<(Box<dyn Module>, String)> {
    // check if os-env path is configured
    if let Ok(path) = env::var(ENV) {
        // error if given an invalid env path
        let Ok(mut f) = File::open(&path) else {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid env path"));
        };
        // check if the given file is valid for each of the supported modules
        for module in modules().into_iter() {
            if module.is_valid(&mut f) {
                return Ok((module, path));
            }
        }
    }
    // iterate modules to attempt to find valid primary-file
    for module in modules().into_iter() {
        let Ok(path) = module.primary_file() else { continue };
        return Ok((module, path.to_owned()));
    }
    // error if no modules were found to work
    Err(Error::new(
        ErrorKind::NotFound,
        "no operating lastlog modules found",
    ))
}

/// Use an auto-selected module to iterate logins for every user account
///
/// This will attempt to find the most relevant database file located on
/// your filesystem and parse it to retrieve the login-records for every
/// user account found in `/etc/passwd`
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
pub fn iter_accounts() -> Result<Vec<Record>> {
    let (module, path) = get_module()?;
    module.iter_accounts(&path)
}

/// Use an auto-selected module to find the last login for a specified user-id
///
/// This will parse through the most relevant database file only until
/// the the given user-id's most recent login is found.
///
/// # Examples
///
/// Basic Usage:
///
/// ```
/// let record = search_uid(1000);
/// ```
pub fn search_uid(uid: u32) -> Result<Record> {
    let (module, path) = get_module()?;
    module.search_uid(uid, &path)
}

/// Use an auto-selected module to find the last login for a specified username
///
/// Similar to `search_uid`, this will only parse the most relevant database
/// file until the given username's most recent login is found.
///
/// # Examples
///
/// Basic Usage:
///
/// ```
/// let record = search_username("foo");
/// ```
pub fn search_username(username: &str) -> Result<Record> {
    let (module, path) = get_module()?;
    module.search_username(username, &path)
}

/// Use libc to retrieve the current user-id and complete a search
#[cfg(feature = "libc")]
pub fn search_self() -> Result<Record> {
    let (module, path) = get_module()?;
    let uid = unsafe { getuid() };
    module.search_uid(uid, &path)
}
