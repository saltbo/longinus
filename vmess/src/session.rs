use crypto::digest::Digest;
use crypto::symmetriccipher::BlockEncryptor;

use std::sync::{Mutex, Arc};
use crate::validator::{TimedUserValidator, MemoryUser};
use std::io::{BufReader, BufRead, Read};
use bytes::buf::ext::Reader;

// md5
macro_rules! md5 {
    ($($x:expr),*) => {{
        let mut digest = crypto::md5::Md5::new();
        let mut result = [0; 16];
        $(digest.input($x);)*
        digest.result(&mut result);
        result
    }}
}

type RequestCommand = u8;

const REQ_CMD_TCP: RequestCommand = 0x01;
const REQ_CMD_UDP: RequestCommand = 0x02;
const REQ_CMD_MUX: RequestCommand = 0x03;

#[derive(Debug)]
pub struct RequestHeader {
    version: u8,
    pub command: RequestCommand,
    option: u8,
    security: i32,
    port: u16,
    // Address  net.Address
    // User: MemoryUser,
}


pub struct ServerSession<'a> {
    user_validator: &'a Arc<Mutex<TimedUserValidator>>,
    // sessionHistory:  *SessionHistory
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    // responseWriter:  io.Writer
    response_header: u8,
}

impl<'a> ServerSession<'a> {
    pub fn new(validator: &'a Arc<Mutex<TimedUserValidator>>) -> Self {
        ServerSession {
            user_validator: validator,
            request_body_key: [0; 16],
            request_body_iv: [0; 16],
            response_body_key: [0; 16],
            response_body_iv: [0; 16],
            response_header: 0,
        }
    }

    pub fn decrypt(&self, reader: &mut Reader<bytes::Bytes>, aescfb: &mut AES128CFB, buf_len: u64) -> Vec<u8> {
        println!("---decrypt---");
        let mut buf = Vec::new();
        reader.take(buf_len).read_to_end(&mut buf);
        println!("raw: {:?}", buf);
        aescfb.decode(&mut buf);
        println!("plain: {:?}", buf);
        return buf;
    }

    pub fn decode_request_header(&mut self, reader: &mut Reader<bytes::Bytes>) -> Result<RequestHeader, &str> {
        let mut key: [u8; 16] = [0; 16];
        reader.read(&mut key);
        println!("{:?}", key);

        let (user, timestamp) = match self.user_validator.lock().unwrap().get(key) {
            None => return Err("invalid user"),
            Some((mem_user, timestamp)) => (*mem_user, timestamp),
        };
        println!("Successful logon!");

        let time = timestamp.to_be_bytes();
        let user_id = user.id().to_vec();
        let header_iv = md5!(&time, &time, &time, &time);
        let header_key = md5!(&user_id, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let mut aescfb = AES128CFB::new(header_key, header_iv);
        let decryptor = self.decrypt(reader, &mut aescfb, 42);

        let mut request = RequestHeader {
            version: *decryptor.get(0).unwrap(),
            command: REQ_CMD_TCP,
            option: 0,
            security: 0,
            port: 0,
        };
        self.request_body_iv.copy_from_slice(decryptor.get(1..17).unwrap());
        self.request_body_key.copy_from_slice(decryptor.get(17..33).unwrap());

        request.option = *decryptor.get(34).unwrap();
        let padding_len = decryptor.get(35).unwrap() >> 4 as i32;
        request.security = (*decryptor.get(35).unwrap() & 0x0F) as i32;
        request.command = RequestCommand::from(*decryptor.get(37).unwrap());
        match request.command {
            REQ_CMD_MUX => {
                // request.Address = net.DomainAddress("v1.mux.cool");
                request.port = 0
            }
            REQ_CMD_TCP | REQ_CMD_UDP => {
                // addrParser.ReadAddressPort(buffer, decryptor)
            }
            _ => {}
        }
        request.port = *decryptor.get(39).unwrap() as u16;
        println!("{:?}", request);
        let port_type = *decryptor.get(40).unwrap();
        println!("{:?}", port_type);

        let addr_len = *decryptor.get(41).unwrap() as u64;
        println!("{:?}", addr_len);

        let addr = self.decrypt(reader, &mut aescfb, addr_len);
        println!("addr: {:?}", addr);

        if padding_len > 0 {
            self.decrypt(reader, &mut aescfb, padding_len as u64);
        }

        let expectedHash = self.decrypt(reader, &mut aescfb, 4);
        println!("expectedHash: {:?}", expectedHash);

        // let actualHash = "";
        // let expectedHash = decryptor.get(58 + *addr_len + padding_len..58 + *addr_len + padding_len + 4);
        // if actualHash != expectedHash {
        //     return Err("invalid auth");
        // }
        //
        Ok(request)
    }

    pub fn decode_request_body(&self, reader: &mut Reader<bytes::Bytes>) -> Vec<u8> {
        let mut len: Vec<u8> = Vec::with_capacity(2);
        reader.take(2).read_to_end(&mut len);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf);
        println!("len: {:?}, data: {:?}", buf.len(), String::from_utf8_lossy(buf.as_slice()));
        return buf;
    }
}


// aes-128-cfb
#[derive(Debug)]
struct AES128CFB {
    key: [u8; 16],
    state: [u8; 16],
    p: usize,
}

impl AES128CFB {
    #[allow(non_snake_case)]
    fn new(key: [u8; 16], IV: [u8; 16]) -> AES128CFB {
        AES128CFB { key, state: IV, p: 16 }
    }

    fn encode(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.p == 16 {
                crypto::aessafe::AesSafe128Encryptor::new(&self.key).encrypt_block(&self.state.clone(), &mut self.state);
                self.p = 0;
            }
            *byte ^= self.state[self.p];
            self.state[self.p] = *byte;
            self.p += 1;
        }
    }

    fn decode(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.p == 16 {
                crypto::aessafe::AesSafe128Encryptor::new(&self.key).encrypt_block(&self.state.clone(), &mut self.state); // yes it's encrypt
                self.p = 0;
            }
            let temp = *byte;
            *byte ^= self.state[self.p];
            self.state[self.p] = temp;
            self.p += 1;
        }
    }
}