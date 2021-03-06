use std::thread;
use std::sync::{Mutex, Arc};
use std::time::Duration;
use std::io::{BufReader, Read};
use bytes::buf::ext::Reader;

use crate::session::{ServerSession};
use crate::validator::TimedUserValidator;
use std::net::TcpStream;
use bytes::{Bytes};


pub struct Vmess {
    clients: Arc<Mutex<TimedUserValidator>>
}

type FnRequest = fn(addr: String, body: Vec<u8>) -> Result<BufReader<TcpStream>, &'static str>;

impl Vmess {
    pub fn new() -> Vmess {
        let validator = Arc::new(Mutex::new(TimedUserValidator::new()));

        let sv = validator.clone();
        thread::spawn(move || {
            loop {
                sv.lock().unwrap().update_user_hash();

                thread::sleep(Duration::from_secs(10))
            }
        });

        Vmess {
            clients: validator
        }
    }

    pub fn process(&self, mut reader: Reader<bytes::Bytes>, request: FnRequest) -> Result<Bytes, &str> {
        let mut srv_session = ServerSession::new(&self.clients);
        let result = srv_session.decode_request_header(&mut reader);
        if result.is_err() {
            println!("{:?}", result.err().unwrap());
            return Err("aaa");
        }

        let req = result.ok().unwrap();
        let body = srv_session.decode_request_body(&mut reader);

        let send_response = request(req.address, body);
        if send_response.is_err() {
            return Err("123");
        }

        let mut buffer: Vec<u8> = Vec::new();
        let mut reader = send_response.ok().unwrap();
        reader.read_to_end(&mut buffer);
        println!("buffer len: {:?}", buffer.len());
        println!("buffer: {:?}", String::from_utf8_lossy(&buffer));

        let encode_response = srv_session.encode_response_body(&buffer);
        Ok(Bytes::from(encode_response))
    }

    pub fn encrypt() {
        // let key: [u8; 16] = [246, 44, 62, 104, 233, 129, 233, 116, 94, 155, 83, 249, 89, 240, 231, 182];
        // let iv: [u8; 16] = [25, 38, 224, 26, 109, 26, 235, 149, 99, 248, 15, 84, 14, 65, 67, 246];
        //
        // let mut data: [u8; 72] = [105, 45, 39, 166, 52, 184, 32, 14, 66, 209, 169, 92, 66, 108, 170, 79, 61, 101, 114, 77,
        //     217, 35, 179, 73, 149, 9, 115, 13, 71, 239, 123, 106, 91, 179, 85, 140, 51, 92, 111, 18,
        //     222, 215, 16, 206, 109, 75, 8, 157, 10, 195, 195, 145, 29, 249, 241, 240, 162, 193, 217,
        //     129, 87, 195, 77, 210, 241, 228, 104, 170, 85, 225, 55, 60];
        //
        // let mut data : [u8; 72] = [1, 153, 220, 107, 134, 179, 216, 9, 56, 121, 38, 70, 58, 254, 203, 194, 236, 186, 240, 99,
        // 222, 116, 219, 112, 129, 155, 37, 38, 240, 76, 191, 234, 229, 56, 5, 21, 0, 1, 0, 80, 2, 23, 110, 111, 116, 105, 102, 
        // 121, 45, 100, 101, 118, 46, 108, 117, 111, 106, 105, 108, 97, 98, 46, 99, 111, 109, 80, 88, 172, 64, 143, 65, 67];
        // println!("{:?}", data.to_vec());
        // AES128CFB::new(key, iv).encode(&mut data);
        // println!("{:?}", data.to_vec());
        // AES128CFB::new(key, iv).decode(&mut data);
        // println!("{:?}", data.to_vec());
    }
}
