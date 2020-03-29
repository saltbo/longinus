use crypto::mac::Mac;
use std::collections::HashMap;
use crate::parse_uid;
use std::time::SystemTime;
use std::process::id;

#[derive(Clone)]
pub struct Account {
    id: [u8; 16],
    alter_ids: Vec<[u8; 16]>,
}

#[derive(Clone)]
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

const CACHE_DURATION_SEC: u64 = 30;

#[derive(Clone)]
pub struct User {
    user: MemoryUser,
    last_sec: u64,
}

pub struct IndexTimePair {
    user: User,
    time_inc: u64,
}

pub fn now_sec() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub struct TimedUserValidator {
    users: Vec<User>,
    user_hash: HashMap<[u8; 16], IndexTimePair>,
    base_time: u64,
}

impl TimedUserValidator {
    pub fn new() -> TimedUserValidator {
        let user_id = parse_uid("f2d17495-9d26-4463-80c1-d8d079dee963").unwrap();
        let user1 = User {
            user: MemoryUser {
                account: Account { id: user_id, alter_ids: vec![] },
                // email: "".to_string(),
                level: 0,
            },
            last_sec: 0,
        };

        TimedUserValidator {
            users: vec![user1],
            user_hash: HashMap::new(),
            base_time: now_sec() - CACHE_DURATION_SEC * 2,
        }
    }

    fn generate_new_hashes(&mut self, now_sec: u64, user: &User) {
        let mut hash_value = [0; 16];
        let gen_end_sec = now_sec + CACHE_DURATION_SEC;
        let mut gen_hash_for_id = |id: &[u8; 16]| {
            let mut gen_begin_sec = user.last_sec;
            if gen_begin_sec < now_sec - CACHE_DURATION_SEC {
                gen_begin_sec = now_sec - CACHE_DURATION_SEC
            }

            println!("time begin: {:?}, time end: {:?}", gen_begin_sec, gen_end_sec);
            for ts in gen_begin_sec..gen_end_sec {
                let mut hmac = crypto::hmac::Hmac::new(crypto::md5::Md5::new(), id);
                hmac.input(&ts.to_be_bytes());
                hmac.raw_result(&mut hash_value);
                hmac.reset();
                self.user_hash.insert(hash_value, IndexTimePair { user: user.clone(), time_inc: ts - self.base_time });
            }
        };

        gen_hash_for_id(&user.user.id());
        for id in user.user.account.alter_ids.clone() {
            gen_hash_for_id(&id)
        }
    }
    fn remove_expired_hashes(&mut self, expire: u64) {
        self.user_hash.retain(|key, pair| {
            pair.time_inc >= expire
        });
    }

    pub fn update_user_hash(&mut self) {
        let now = now_sec();
        for user in self.users.clone() {
            self.generate_new_hashes(now, &user);
        }

        // remove the expired hashes
        let expire = now - CACHE_DURATION_SEC;
        if expire > self.base_time {
            self.remove_expired_hashes(expire - self.base_time)
        }
    }

    pub fn add(&mut self, user: MemoryUser) {
        let now_sec = now_sec();

        let uu = User {
            user,
            last_sec: now_sec - CACHE_DURATION_SEC,
        };
        self.users.push(uu.clone());
        self.generate_new_hashes(now_sec, &uu);
    }

    pub fn get(&self, user_hash: [u8; 16]) -> Option<(&MemoryUser, u64)> {
        match self.user_hash.get(&user_hash) {
            None => None,
            Some(pair) => { Some((&pair.user.user, pair.time_inc + self.base_time)) }
        }
    }
    
    pub fn del(&self) {

    }
}
