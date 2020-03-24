use std::time::{Duration, Instant};

use actix::prelude::*;
use actix_files as fs;
use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_actors::ws;
use actix_web::client::Client;

use std::thread;
use vmess::Vmess;
use std::net::TcpStream;
use std::io::{Write, BufReader, BufRead, Read, Take};
use bytes::Bytes;
use bytes::buf::BufExt;

extern crate timer;
extern crate chrono;


/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// do websocket handshake and start `MyWebSocket` actor
async fn ws_index(r: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    println!("{:?}", r);
    let res = ws::start(MyWebSocket::new(), &r, stream);
    println!("{:?}", res);
    res
}

/// websocket connection is long running connection, it easier
/// to handle with an actor
struct MyWebSocket {
    /// Client must send ping at least once per 10 seconds (CLIENT_TIMEOUT),
    /// otherwise we drop connection.
    hb: Instant,
    vmess: Vmess,
}

impl Actor for MyWebSocket {
    type Context = ws::WebsocketContext<Self>;

    /// Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

/// Handler for `ws::Message`
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for MyWebSocket {
    fn handle(
        &mut self,
        msg: Result<ws::Message, ws::ProtocolError>,
        ctx: &mut Self::Context,
    ) {
        // process websocket messages
        println!("WS: {:?}", msg);
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => {
                self.vmess.decode(bin.reader());

                // println!("{:?}", body);
                // let mut stream = TcpStream::connect("39.96.250.224:80").expect("Could not connect to server");
                // stream.write(&body.to_vec()).expect("Failed to write to server");
                //
                // let mut reader = BufReader::new(&stream);
                // let mut buffer: Vec<u8> = Vec::new();
                // reader.read_to_end(&mut buffer)
                //     .expect("Could not read into buffer");
                // print!(
                //     "{}",
                //     String::from_utf8(buffer).expect("Could not write buffer as string")
                // );

                // let rb =  EncodeResponseBody

                ctx.binary("")
            }
            Ok(ws::Message::Close(_)) => {
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

impl MyWebSocket {
    fn new() -> Self {
        Self { hb: Instant::now(), vmess: Vmess::new() }
    }

    /// helper method that sends ping to client every second.
    ///
    /// also this method checks heartbeats from client
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                println!("Websocket Client heartbeat failed, disconnecting!");

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping(b"");
        });
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let timer = timer::Timer::new();
    let _guard = {
        timer.schedule_repeating(chrono::Duration::seconds(10), move || {
            // Vmess::update_userhash(user_id);
        })
    };
    Vmess::encrypt();

    std::env::set_var("RUST_LOG", "actix_server=info,actix_web=info");
    env_logger::init();

    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // websocket route
            .service(web::resource("/ray").route(web::get().to(ws_index)))
            // static files
            .service(fs::Files::new("/", "static/").index_file("index.html"))
    })
        // start http server on 127.0.0.1:8080
        .bind("127.0.0.1:8080")?
        .run()
        .await
}