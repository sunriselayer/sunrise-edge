//! A real loopback TCP relay observes HTTP POSTs without substituting protocol
//! responses. Used only for explicit preflight zero-network assertions.
#![allow(dead_code)]
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct HttpRelay {
    pub addr: SocketAddr,
    pub posts: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl HttpRelay {
    pub fn new(backend: SocketAddr) -> Self {
        let listener: TcpListener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let posts: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let stopped: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let count = posts.clone();
        let shutdown = stopped.clone();
        let worker: JoinHandle<()> = thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut client, _)) => {
                        client
                            .set_read_timeout(Some(Duration::from_secs(10)))
                            .unwrap();
                        client
                            .set_write_timeout(Some(Duration::from_secs(10)))
                            .unwrap();
                        let mut header: Vec<u8> = Vec::new();
                        while !header.ends_with(b"\r\n\r\n") {
                            let mut byte: [u8; 1] = [0];
                            if client.read_exact(&mut byte).is_err() {
                                break;
                            }
                            header.push(byte[0]);
                            assert!(header.len() <= 16 * 1024);
                        }
                        if !header.ends_with(b"\r\n\r\n") {
                            continue;
                        }
                        if header.starts_with(b"POST ") {
                            count.fetch_add(1, Ordering::SeqCst);
                        }
                        let header_text: &str = std::str::from_utf8(&header).unwrap();
                        let length: usize = header_text
                            .lines()
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                key.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        assert!(length <= 8 * 1024 * 1024);
                        let mut body: Vec<u8> = vec![0; length];
                        client.read_exact(&mut body).unwrap();
                        let mut server: TcpStream =
                            TcpStream::connect_timeout(&backend, Duration::from_secs(5)).unwrap();
                        server
                            .set_read_timeout(Some(Duration::from_secs(10)))
                            .unwrap();
                        server
                            .set_write_timeout(Some(Duration::from_secs(10)))
                            .unwrap();
                        server.write_all(&header).unwrap();
                        server.write_all(&body).unwrap();
                        std::io::copy(&mut server, &mut client).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("test HTTP relay accept failed: {error}"),
                }
            }
        });
        Self {
            addr,
            posts,
            stopped,
            worker: Some(worker),
        }
    }
}
impl Drop for HttpRelay {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
