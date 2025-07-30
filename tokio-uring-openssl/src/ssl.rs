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
