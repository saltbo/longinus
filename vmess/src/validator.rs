use std::collections::HashMap;

pub struct Account {
    id: [u8; 16]
}

pub struct MemoryUser {
    // Account is the parsed account of the protocol.
    pub account: Account,
    email: String,
    level: u32,
}

impl MemoryUser {
    pub fn id(&self) -> [u8; 16] {
        self.account.id
    }
}

pub struct User {
    user: MemoryUser,
    last_sec: i64,
}

pub struct IndexTimePair {
    user: User,
    time_inc: u64,
}

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

    pub fn get(&self, user_hash: [u8; 16]) -> Option<(&MemoryUser, u64)> {
        match self.user_hash.get(&user_hash) {
            None => None,
            Some(pair) => { Some((&pair.user.user, pair.time_inc + self.base_time as u64)) }
        }
    }
}
