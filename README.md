# lastlog

Simple crate for retrieving latest last-login records on a UNIX system

The basic usage looks like:
```rust,no_run
use lastlog::{search_uid, search_username};

fn main() {
  let result1 = search_uid(1000);
  let result2 = search_username("foo");
}
```

NOTE: this functionality is only designed to work with UNIX systems
that support either utmp/wtmp of lastlog database types.


