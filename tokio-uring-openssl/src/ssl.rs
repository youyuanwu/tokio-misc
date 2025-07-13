use std::io::Read;

use crate::io::{AsyncRead, AsyncWrite, SyncStream};

#[derive(Debug)]
pub enum HandshakeError {
    IO(std::io::Error),
    Ssl(openssl::ssl::Error),
}

pub struct SslStream<S> {
    ssl: openssl::ssl::SslStream<SyncStream>,
    tcp: S,
}

impl<S> SslStream<S> {
    pub fn new(ssl: openssl::ssl::Ssl, s: S) -> Result<Self, openssl::error::ErrorStack> {
        let sync = SyncStream::create();
        Ok(Self {
            ssl: openssl::ssl::SslStream::new(ssl, sync)?,
            tcp: s,
        })
    }
}

impl<S: AsyncRead + AsyncWrite> SslStream<S> {
    pub async fn connect(&mut self) -> Result<(), HandshakeError> {
        loop {
            // println!("client connect loop");
            match self.ssl.connect() {
                Ok(()) => {
                    self.flush_write_buf().await.map_err(HandshakeError::IO)?;
                    return Ok(());
                }
                Err(e) => {
                    // println!("debug {e:?}");
                    match e.into_io_error() {
                        Ok(io_e) => {
                            if io_e.kind() == std::io::ErrorKind::WouldBlock {
                                // keep the data flowing.
                                let len =
                                    self.flush_write_buf().await.map_err(HandshakeError::IO)?;

                                if len == 0 {
                                    self.fill_read_buf().await.map_err(HandshakeError::IO)?;
                                }
                            }
                        }
                        Err(e) => return Err(HandshakeError::Ssl(e)),
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead> SslStream<S> {
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.ssl.read(buf) {
                Ok(len) => return Ok(len),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        // continue filling until ssl has enough data.
                        match self.fill_read_buf().await {
                            Ok(_) => continue,
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }
    }

    async fn fill_read_buf(&mut self) -> std::io::Result<()> {
        self.ssl.get_mut().fill_read_buf(&mut self.tcp).await
    }
}

impl<S: AsyncWrite> SslStream<S> {
    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let res = std::io::Write::write(&mut self.ssl, buf);
            match res {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    match self.flush_write_buf().await {
                        Ok(_) => continue,
                        Err(e) => return Err(e),
                    }
                }
                _ => {
                    self.flush_write_buf().await?;
                    return res;
                }
            }
        }
    }

    async fn flush_write_buf(&mut self) -> std::io::Result<usize> {
        self.ssl.get_mut().flush_write_buf(&mut self.tcp).await
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use openssl::ssl::{SslConnector, SslVersion};

    use crate::io::UTcpStream;

    pub mod ssl_gen {
        //! A program that generates ca certs, certs verified by the ca, and public
        //! and private keys.

        use openssl::asn1::Asn1Time;
        use openssl::bn::{BigNum, MsbOption};
        use openssl::error::ErrorStack;
        use openssl::hash::MessageDigest;
        use openssl::pkey::{PKey, Private};
        use openssl::rsa::Rsa;
        use openssl::x509::extension::{
            BasicConstraints, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier,
        };
        use openssl::x509::{X509, X509NameBuilder};

        /// Make a self signed certificate and private key using openssl
        pub fn mk_self_signed_cert(
            subject_alt_names: Vec<String>,
        ) -> Result<(X509, PKey<Private>), ErrorStack> {
            let rsa = Rsa::generate(2048)?;
            let key_pair = PKey::from_rsa(rsa)?;

            let mut x509_name = X509NameBuilder::new()?;
            x509_name.append_entry_by_text("C", "US")?;
            x509_name.append_entry_by_text("ST", "TX")?;
            x509_name.append_entry_by_text("O", "Some CA organization")?;
            x509_name.append_entry_by_text("CN", "self test")?;
            let x509_name = x509_name.build();

            let mut cert_builder = X509::builder()?;
            cert_builder.set_version(2)?;
            let serial_number = {
                let mut serial = BigNum::new()?;
                serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
                serial.to_asn1_integer()?
            };
            cert_builder.set_serial_number(&serial_number)?;
            cert_builder.set_subject_name(&x509_name)?;
            cert_builder.set_issuer_name(&x509_name)?;
            cert_builder.set_pubkey(&key_pair)?;
            let not_before = Asn1Time::days_from_now(0)?;
            cert_builder.set_not_before(&not_before)?;
            let not_after = Asn1Time::days_from_now(365)?;
            cert_builder.set_not_after(&not_after)?;

            cert_builder.append_extension(BasicConstraints::new().build()?)?; // not ca
            cert_builder.append_extension(
                KeyUsage::new()
                    .critical()
                    .non_repudiation()
                    .digital_signature()
                    .key_encipherment()
                    .build()?,
            )?;

            // add dns
            let mut subject_alt_name_ex = SubjectAlternativeName::new();
            for name in subject_alt_names {
                subject_alt_name_ex.dns(name.as_str());
            }
            let subject_alt_name_ex =
                subject_alt_name_ex.build(&cert_builder.x509v3_context(None, None))?;
            cert_builder.append_extension(subject_alt_name_ex)?;

            let subject_key_identifier =
                SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
            cert_builder.append_extension(subject_key_identifier)?;

            cert_builder.sign(&key_pair, MessageDigest::sha256())?;
            let cert = cert_builder.build();

            Ok((cert, key_pair))
        }
    }

    pub fn create_openssl_acceptor(
        cert: &openssl::x509::X509,
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> openssl::ssl::SslAcceptor {
        let mut acceptor =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .unwrap();
        acceptor.set_private_key(key).unwrap();
        acceptor.set_certificate(cert).unwrap();
        acceptor.cert_store_mut().add_cert(cert.clone()).unwrap();
        acceptor.check_private_key().unwrap();
        acceptor
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        // require client to present cert with matching subject name.
        acceptor.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |ok, ctx| {
            if !ok {
                let e = ctx.error();
                println!("verify failed : {e}");
            }
            ok
        });
        acceptor.build()
    }

    pub fn create_openssl_connector(cert: &openssl::x509::X509) -> SslConnector {
        let mut connector =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
        connector.cert_store_mut().add_cert(cert.clone()).unwrap();
        connector.add_client_ca(cert).unwrap();
        connector.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |ok, ctx| {
            if !ok {
                let e = ctx.error();
                println!("verify failed : {e}");
            }
            ok
        });
        // connector
        //     .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
        //     .unwrap();
        connector
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        connector.build()
    }

    const HELLO: &str = "hello";

    #[test]
    fn ssl_test() {
        let l = std::net::TcpListener::bind("localhost:0").unwrap();
        let l_addr = l.local_addr().unwrap();

        let (cert, key_pair) = ssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();

        let ssl_acpt = create_openssl_acceptor(&cert, &key_pair);
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
            let mut ssl_s = crate::ssl::SslStream::new(ctx, UTcpStream(stream)).unwrap();
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
