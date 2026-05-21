//! Code from cyper_core.

use hyper::{
    HeaderMap,
    header::{Entry, HeaderValue, OccupiedEntry},
};

pub fn basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
    U: std::fmt::Display,
    P: std::fmt::Display,
{
    use std::io::Write;

    use base64::{prelude::BASE64_STANDARD, write::EncoderWriter};

    let mut buf = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
        let _ = write!(encoder, "{username}:");
        if let Some(password) = password {
            let _ = write!(encoder, "{password}");
        }
    }
    let mut header = HeaderValue::from_bytes(&buf).expect("base64 is always valid HeaderValue");
    header.set_sensitive(true);
    header
}

pub(crate) fn replace_headers(dst: &mut HeaderMap, src: HeaderMap) {
    // IntoIter of HeaderMap yields (Option<HeaderName>, HeaderValue).
    // The first time a name is yielded, it will be Some(name), and if
    // there are more values with the same name, the next yield will be
    // None.

    let mut prev_entry: Option<OccupiedEntry<_>> = None;
    for (key, value) in src {
        match key {
            Some(key) => match dst.entry(key) {
                Entry::Occupied(mut e) => {
                    e.insert(value);
                    prev_entry = Some(e);
                }
                Entry::Vacant(e) => {
                    let e = e.insert_entry(value);
                    prev_entry = Some(e);
                }
            },
            None => match prev_entry {
                Some(ref mut entry) => {
                    entry.append(value);
                }
                None => unreachable!("HeaderMap::into_iter yielded None first"),
            },
        }
    }
}

#[cfg(feature = "multipart")]
pub(crate) fn fast_random() -> u64 {
    use std::{
        cell::Cell,
        collections::hash_map::RandomState,
        hash::{BuildHasher, Hasher},
    };

    thread_local! {
        static KEY: RandomState = RandomState::new();
        static COUNTER: Cell<u64> = const { Cell::new(0) };
    }

    KEY.with(|key| {
        COUNTER.with(|ctr| {
            let n = ctr.get().wrapping_add(1);
            ctr.set(n);

            let mut h = key.build_hasher();
            h.write_u64(n);
            h.finish()
        })
    })
}
