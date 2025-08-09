use tokio_uring::{
    BufResult,
    buf::{BoundedBuf, BoundedBufMut},
    net::TcpStream,
};

#[allow(async_fn_in_trait)]
pub trait AsyncRead {
    async fn read<B: BoundedBufMut>(&mut self, buf: B) -> BufResult<usize, B>;
}

#[allow(async_fn_in_trait)]
pub trait AsyncWrite {
    async fn write_all<T: BoundedBuf>(&self, buf: T) -> BufResult<(), T>;

    /// Shutdown the write side of the connection
    async fn shutdown(&mut self) -> std::io::Result<()>;
}

pub struct UTcpStream(pub TcpStream);

impl AsyncRead for UTcpStream {
    async fn read<B: BoundedBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        self.0.read(buf).await
    }
}

impl AsyncWrite for UTcpStream {
    async fn write_all<T: BoundedBuf>(&self, buf: T) -> BufResult<(), T> {
        self.0.write_all(buf).await
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        // Shutdown the write side of the TCP connection
        use std::net::Shutdown;
        self.0.shutdown(Shutdown::Write)
    }
}
