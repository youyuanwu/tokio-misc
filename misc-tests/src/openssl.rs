mod tests {
    use std::io::{Read, Write};

    use tokio_uring_openssl::io::UTcpStream;

    use crate::utils::{HELLO, create_openssl_acceptor_builder, create_openssl_connector};

    #[test]
    fn ssl_test() {
        let l = std::net::TcpListener::bind("localhost:0").unwrap();
        let l_addr = l.local_addr().unwrap();

        let (cert, key_pair) =
            crate::utils::ssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();

        let ssl_acpt = create_openssl_acceptor_builder(&cert, &key_pair).build();
        let ssl_con = create_openssl_connector(&cert).configure().unwrap();

        let svr = std::thread::spawn(move || {
            println!("accept server tcp");
            let (s, _) = l.accept().unwrap();
            println!("accept server ssl");
            let mut ssl_s = ssl_acpt.accept(s).unwrap();
            println!("server read");
            let mut buf = [0_u8; 100];
            let len = ssl_s.read(buf.as_mut_slice()).unwrap();
            assert_eq!(len, HELLO.len());
            assert_eq!(&buf[0..len], HELLO.as_bytes());

            // write back 2 hellos
            println!("server write");
            ssl_s.write_all(HELLO.as_bytes()).unwrap();
            println!("server write2");
            ssl_s.write_all(HELLO.as_bytes()).unwrap();
            ssl_s.shutdown().unwrap();
        });

        std::thread::sleep(std::time::Duration::from_secs(1));

        tokio_uring::start(async move {
            println!("client tcp conn");
            let stream = tokio_uring::net::TcpStream::connect(l_addr).await.unwrap();

            let ctx = ssl_con.into_ssl("localhost").unwrap();
            let mut ssl_s =
                tokio_uring_openssl::ssl::SslStream::new(ctx, UTcpStream(stream)).unwrap();
            println!("client ssl conn");
            ssl_s.connect().await.unwrap();
            println!("client ssl write");
            let len = ssl_s.write(HELLO.as_bytes()).await.unwrap();
            assert_eq!(len, HELLO.len());

            let mut data = Vec::new();
            loop {
                let mut buf = [0_u8; 100];
                let len = ssl_s.read(buf.as_mut_slice()).await.unwrap();
                if len == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..len]);
            }
            assert_eq!(data.len(), 2 * HELLO.len());
        });

        svr.join().unwrap();
    }
}
