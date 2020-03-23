
use crypto::mac::Mac;
use std::collections::HashMap;
use crate::parse_uid;

#[derive(Clone, Copy)]
pub struct Account {
    id: [u8; 16]
}

#[derive(Clone, Copy)]
pub struct MemoryUser {
    // Account is the parsed account of the protocol.
    pub account: Account,
    // email: String,
    level: u32,
}

impl MemoryUser {
    pub fn id(&self) -> [u8; 16] {
        self.account.id
    }
}

#[derive(Clone, Copy)]
pub struct User {
    user: MemoryUser,
    last_sec: i64,
}

#[derive(Clone, Copy)]
pub struct IndexTimePair {
    user: User,
    time_inc: u64,
}

// #[derive(Send, Sync)]
pub struct TimedUserValidator {
    users: Vec<User>,
    user_hash: HashMap<[u8; 16], IndexTimePair>,
    base_time: i64,
}

impl TimedUserValidator {
    pub fn new() -> TimedUserValidator {
        TimedUserValidator {
            users: vec![],
            user_hash: HashMap::new(),
            base_time: 0,
        }
    }

    fn generate_new_hashes(&mut self, user: User) {
        println!("1111: {:?}", user.user.account.id);

        let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let end_sec = time + 120;
        let mut begin_sec = time - 120;

        println!("time begin: {:?}, time end: {:?}", begin_sec, end_sec);
        while begin_sec != end_sec {
            begin_sec = begin_sec + 1;

            let mut auth_hash = [0; 16];
            let mut hmac = crypto::hmac::Hmac::new(crypto::md5::Md5::new(), &user.user.account.id);
            hmac.input(&begin_sec.to_be_bytes());
            hmac.raw_result(&mut auth_hash);

            let it = IndexTimePair { user, time_inc: begin_sec };

            // println!("{:?}: {:?}", it.time, hex::encode(auth_hash));
            self.user_hash.insert(auth_hash, it);
        }

        // for (key, value) in self.user_hash {
        //     println!("{:?}: {:?}", key, value.time);
        // }
    }

    pub fn update_user_hash(&mut self) {
        let user_id = parse_uid("f2d17495-9d26-4463-80c1-d8d079dee963").unwrap();
        let uu = User {
            user: MemoryUser {
                account: Account { id: user_id },
                // email: "".to_string(),
                level: 0,
            },
            last_sec: 0,
        };
        self.generate_new_hashes(uu);
    }

    pub fn get(&self, user_hash: [u8; 16]) -> Option<(&MemoryUser, u64)> {
        match self.user_hash.get(&user_hash) {
            None => None,
            Some(pair) => { Some((&pair.user.user, pair.time_inc + self.base_time as u64)) }
        }
    }
}
