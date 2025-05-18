/**
 * Windows API Reader
 */
use std::io::{Error, ErrorKind};
use std::time::{Duration, UNIX_EPOCH};

use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetUserEnum, FILTER_NORMAL_ACCOUNT, MAX_PREFERRED_LENGTH, USER_INFO_3,
};
use windows_sys::Win32::System::WindowsProgramming::GetUserNameW;

use crate::common::*;

/* Function */

fn wstr_string(ptr: *mut u16) -> Result<String, std::string::FromUtf16Error> {
    let mut str = Vec::<u16>::new();
    let mut i = 0;
    unsafe {
        while *ptr.add(i) != 0 {
            str.push(*ptr.add(i));
            i += 1;
        }
    }
    return String::from_utf16(&str);
}

//NOTE: when some windows machines are configured with a local account
// and later add a MS account, sometimes the lastlogin record can seemingly
// be linked to the wrong account. The login timestamp gets attached
// to `defaultuserX` rather than their record.
fn get_latest_default(records: &Vec<Record>) -> Option<LoginTime> {
    let only_defaults = records.iter().all(|r| match r.last_login {
        LoginTime::Never => true,
        LoginTime::Last(_) if r.name.starts_with("defaultuser") => true,
        _ => false,
    });
    if !only_defaults {
        return None;
    }
    let index = records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.name.starts_with("defaultuser"))
        .filter(|(_, r)| r.last_login != LoginTime::Never)
        .max_by(|(_, r1), (_, r2)| {
            let t1 = match &r1.last_login {
                LoginTime::Last(t1) => t1,
                _ => &std::time::SystemTime::UNIX_EPOCH,
            };
            let t2 = match &r2.last_login {
                LoginTime::Last(t2) => t2,
                _ => &std::time::SystemTime::UNIX_EPOCH,
            };
            t1.cmp(t2)
        })
        .map(|(n, _)| n)
        .expect("unable to find default user");
    Some(records[index].last_login.clone())
}

/// Retrieve Current Username via WinAPI
pub fn get_username() -> std::io::Result<String> {
    // get size of username
    let mut size = 0;
    let rc = unsafe { GetUserNameW(std::ptr::null_mut(), &mut size) };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    // retrieve username
    let mut v: Vec<u16> = Vec::with_capacity(255);
    unsafe {
        let rc = GetUserNameW(v.as_mut_ptr(), &mut size);
        if rc == 0 {
            return Err(Error::last_os_error());
        }
        v.set_len(size.try_into().unwrap())
    };
    let name = String::from_utf16_lossy(&v);
    Ok(name.trim_matches('\0').to_owned())
}

/* Implementation */

/// Windows COM API Reader
///
/// This module allows for reading windows login records related to system
/// users by accessing the [Windows API](https://github.com/microsoft/windows-rs)
///
/// # Examples
///
/// Basic Usage:
/// ```
/// use lastlog::Windows;
///
/// let win    = lastlog::Windows;
/// let record = win.search_uid(1001, "");
/// ```
pub struct Windows {}

impl LoginDB for Windows {
    fn is_valid(&self, _f: &mut std::fs::File) -> bool {
        true
    }

    fn primary_file(&self) -> std::io::Result<&'static str> {
        Ok("")
    }

    fn iter_accounts(&self, _fname: &str) -> std::io::Result<Vec<Record>> {
        let servername = std::ptr::null_mut();
        let level = 3; // USER_INFO_3
        let mut bufptr = std::ptr::null_mut::<u8>();
        let mut entriesread = 0;
        let mut totalentries = 0;
        let mut resume_handle = 0;

        let rc = unsafe {
            NetUserEnum(
                servername,
                level,
                FILTER_NORMAL_ACCOUNT,
                &mut bufptr,
                MAX_PREFERRED_LENGTH,
                &mut entriesread,
                &mut totalentries,
                &mut resume_handle,
            )
        };
        if rc != NERR_Success {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Windows Error: {rc:?}"),
            ));
        }

        let accounts = unsafe {
            std::slice::from_raw_parts(
                bufptr as *const u8 as *const USER_INFO_3,
                entriesread as usize,
            )
        };

        let mut records = Vec::<Record>::with_capacity(entriesread as usize);
        for account in accounts {
            let name = wstr_string(account.usri3_name).expect("invalid utf-16 username");
            let last_login = match account.usri3_last_logon {
                0 => LoginTime::Never,
                _ => {
                    let secs = Duration::new(account.usri3_last_logon as u64, 0);
                    LoginTime::Last(UNIX_EPOCH + secs)
                }
            };
            records.push(Record {
                rtype: RecordType::User,
                name,
                uid: Some(account.usri3_user_id),
                tty: "N/A".to_owned(),
                last_login,
            });
        }
        Ok(records)
    }

    fn search_username(&self, username: &str, fname: &str) -> std::io::Result<Record> {
        let records = self.iter_accounts(fname)?;
        let latest = get_latest_default(&records);
        for mut record in records {
            if username == record.name {
                if let Some(latest) = latest {
                    record.last_login = latest;
                }
                return Ok(record);
            }
        }
        Err(Error::new(ErrorKind::InvalidInput, "no such user"))
    }

    fn search_uid(&self, uid: u32, fname: &str) -> std::io::Result<Record> {
        let records = self.iter_accounts(fname)?;
        let latest = get_latest_default(&records);
        for mut record in records {
            let Some(ruid) = record.uid.as_ref() else {
                continue;
            };
            if &uid == ruid {
                if let Some(latest) = latest {
                    record.last_login = latest;
                }
                return Ok(record);
            }
        }
        Err(Error::new(ErrorKind::InvalidInput, "no such user"))
    }
}
