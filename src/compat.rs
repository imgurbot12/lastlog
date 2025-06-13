#[cfg(target_os = "windows")]
pub mod os {
    use crate::winapi;
    use crate::{common::*, Record};
    use std::io::Result;

    #[inline]
    pub fn modules() -> Vec<Box<dyn LoginDB>> {
        vec![Box::new(winapi::Windows {})]
    }

    #[inline]
    pub fn search_self(module: Box<dyn LoginDB>, path: String) -> Result<Record> {
        let username = winapi::get_username()?;
        module.search_username(&username, &path)
    }
}

#[cfg(target_family = "unix")]
pub mod os {
    use crate::{common::*, Record};
    use crate::{lastlog, utmp};
    use std::io::Result;

    #[inline]
    pub fn modules() -> Vec<Box<dyn LoginDB>> {
        vec![Box::new(utmp::Utmp {}), Box::new(lastlog::LastLog {})]
    }

    #[cfg(feature = "libc")]
    #[inline]
    fn get_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    #[cfg(not(feature = "libc"))]
    #[inline]
    fn get_uid() -> u32 {
        guess_uid()
    }

    #[inline]
    pub fn search_self(module: Box<dyn LoginDB>, path: String) -> Result<Record> {
        let uid = get_uid();
        module.search_uid(uid, &path)
    }
}
