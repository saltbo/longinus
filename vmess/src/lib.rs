mod vmess;
mod session;
mod validator;
mod address;

pub use vmess::*;
pub use session::RequestHeader;

pub trait SizedMonadExt: Sized {
    fn apply<F: FnOnce(&mut Self)>(mut self, f: F) -> Self {
        f(&mut self); self
    }
}

impl<T: Sized> SizedMonadExt for T {}

pub fn parse_uid(x: &str) -> Option<[u8; 16]> {
    let x = x.replace('-', "");
    let list: Vec<_> = (0..32).step_by(2).map(|i| u8::from_str_radix(&x[i..i+2], 16).unwrap()).collect();
    list.get(0..16).map(|x| [0; 16].apply(|buf| buf.copy_from_slice(x)))
}

