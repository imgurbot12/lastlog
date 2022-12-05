# lastlog

A simple user crate designed to read `/var/log/lastlog`
for retrieving last-login records on linux systems

---

The basic usage looks like:

```rust
use lastlog::{search_uid, search_username};

fn main() {
  let result1 = search_uid(1000);
  let result2 = search_username("foo");
}
```

NOTE: this functionality will ONLY work on **UNIX** operating
systems that support the `/var/log/lastlog` database

