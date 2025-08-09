use crate::{AsyncRead, AsyncWrite};
use futures_util::io::{AsyncRead as FutAsyncRead, AsyncWrite as FutAsyncWrite};
use pin_project_lite::pin_project;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

type PinBoxFuture<T> = Pin<Box<dyn std::future::Future<Output = T>>>;

/// Wraps async stream into sync stream.
/// The sync methods will return [`std::io::ErrorKind::WouldBlock`] error if the
/// inner buffer needs more data.
pub struct SyncStream<S> {
    inner: S,
    read_buffer: VecDeque<u8>,
    write_buffer: Vec<u8>,
    eof: bool,
}

impl<S: AsyncRead + AsyncWrite> SyncStream<S> {
    /// Create a new SyncStream with default buffer capacity
    pub fn new(stream: S) -> Self {
        Self::with_capacity(8192, stream)
    }

    /// Create a new SyncStream with specified buffer capacity
    pub fn with_capacity(capacity: usize, stream: S) -> Self {
        Self {
            inner: stream,
            read_buffer: VecDeque::with_capacity(capacity),
            write_buffer: Vec::with_capacity(capacity),
            eof: false,
        }
    }

    /// Get if the stream is at EOF
    pub fn is_eof(&self) -> bool {
        self.eof
    }

    /// Get reference to the inner stream
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get mutable reference to the inner stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

fn would_block(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::WouldBlock, msg)
}

impl<S: AsyncRead + AsyncWrite> SyncStream<S> {
    /// Fill the read buffer by reading from the async stream
    pub async fn fill_read_buf(&mut self) -> std::io::Result<usize> {
        if self.eof {
            return Ok(0);
        }

        // Create a buffer to read into
        const BUFFER_SIZE: usize = 8192;
        let read_buf = vec![0u8; BUFFER_SIZE];

        // Read from the async stream
        let (result, returned_buf) = self.inner.read(read_buf).await;

        match result {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    self.eof = true;
                    return Ok(0);
                }

                // Add the data to our read buffer
                for &byte in &returned_buf[..bytes_read] {
                    self.read_buffer.push_back(byte);
                }

                Ok(bytes_read)
            }
            Err(e) => Err(e),
        }
    }

    /// Flush the write buffer to the async stream
    pub async fn flush_write_buf(&mut self) -> std::io::Result<usize> {
        if self.write_buffer.is_empty() {
            return Ok(0);
        }

        // Take the data from the write buffer, preserving capacity
        let capacity = self.write_buffer.capacity();
        let data = std::mem::take(&mut self.write_buffer);
        let len = data.len();

        // Restore the capacity of the write buffer
        self.write_buffer.reserve_exact(capacity);

        // Write to the async stream
        let (result, _returned_buf) = self.inner.write_all(data).await;

        match result {
            Ok(()) => Ok(len),
            Err(e) => Err(e),
        }
    }

    /// Shutdown the stream - flush and close
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        // First flush any pending write data
        self.flush_write_buf().await?;
        // Then shutdown the connection
        self.inner.shutdown().await
    }
}

impl<S> std::io::Read for SyncStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // If we have buffered data, use it first
        if !self.read_buffer.is_empty() {
            let to_copy = buf.len().min(self.read_buffer.len());
            for item in buf.iter_mut().take(to_copy) {
                *item = self.read_buffer.pop_front().unwrap();
            }
            return Ok(to_copy);
        }

        // If we've reached EOF and have no buffered data, return 0
        if self.eof {
            return Ok(0);
        }

        // No buffered data and not EOF - need to fill buffer
        Err(would_block("need to fill the read buffer"))
    }
}

impl<S> std::io::Write for SyncStream<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Check if we need to flush existing buffer first
        if self.write_buffer.len() + buf.len() > self.write_buffer.capacity()
            && !self.write_buffer.is_empty()
        {
            return Err(would_block("need to flush the write buffer"));
        }

        // Buffer the data
        let to_write = buf
            .len()
            .min(self.write_buffer.capacity() - self.write_buffer.len());
        self.write_buffer.extend_from_slice(&buf[..to_write]);
        Ok(to_write)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.write_buffer.is_empty() {
            Err(would_block("need to flush the write buffer"))
        } else {
            Ok(())
        }
    }
}

pin_project! {
    /// Async stream adaptor
    /// For futures_util::AsyncRead and futures_util::AsyncWrite
    pub struct AsyncStream<S> {
        #[pin]
        inner: SyncStream<S>,
        read_future: Option<PinBoxFuture<std::io::Result<usize>>>,
        write_future: Option<PinBoxFuture<std::io::Result<usize>>>,
        shutdown_future: Option<PinBoxFuture<std::io::Result<()>>>,
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncStream<S> {
    /// Create AsyncStream with the stream and default buffer size
    pub fn new(stream: S) -> Self {
        Self::new_impl(SyncStream::new(stream))
    }

    /// Create AsyncStream with the stream and buffer size
    pub fn with_capacity(cap: usize, stream: S) -> Self {
        Self::new_impl(SyncStream::with_capacity(cap, stream))
    }

    fn new_impl(inner: SyncStream<S>) -> Self {
        Self {
            inner,
            read_future: None,
            write_future: None,
            shutdown_future: None,
        }
    }

    /// Get the reference of the inner stream
    pub fn get_ref(&self) -> &S {
        self.inner.get_ref()
    }
}

impl<S: AsyncRead + AsyncWrite + 'static> FutAsyncRead for AsyncStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();

        // Safety: We're pinning the inner SyncStream but it's safe because
        // we control the lifetime and the stream won't be moved.
        let inner: &'static mut SyncStream<S> =
            unsafe { &mut *(this.inner.get_unchecked_mut() as *mut _) };

        // Check if we have an ongoing read future
        if let Some(mut f) = this.read_future.take() {
            if f.as_mut().poll(cx).is_pending() {
                // Future is still pending, put it back and return
                this.read_future.replace(f);
                return Poll::Pending;
            }
            // Future completed, continue to try sync read
        }

        // Try the sync read operation
        match std::io::Read::read(inner, buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Need to fill the read buffer asynchronously
                this.read_future.replace(Box::pin(inner.fill_read_buf()));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + 'static> FutAsyncWrite for AsyncStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();

        let inner: &'static mut SyncStream<S> =
            unsafe { &mut *(this.inner.get_unchecked_mut() as *mut _) };

        // Check if we have an ongoing write future
        if let Some(mut f) = this.write_future.take() {
            if f.as_mut().poll(cx).is_pending() {
                // Future is still pending, put it back and return
                this.write_future.replace(f);
                return Poll::Pending;
            }
            // Future completed, continue to try sync write
        }

        // Try the sync write operation
        match std::io::Write::write(inner, buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Need to flush the write buffer asynchronously
                this.write_future.replace(Box::pin(inner.flush_write_buf()));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();

        // If shutdown is in progress, we can't flush anymore since shutdown
        // includes flushing. Just report that flush is complete.
        if this.shutdown_future.is_some() {
            return Poll::Ready(Ok(()));
        }

        let inner: &'static mut SyncStream<S> =
            unsafe { &mut *(this.inner.get_unchecked_mut() as *mut _) };

        // Check if we have an ongoing write operation
        let res = if let Some(mut f) = this.write_future.take() {
            // Continue polling the existing write future
            match f.as_mut().poll(cx) {
                Poll::Pending => {
                    // Still in progress, put the future back and return
                    this.write_future.replace(f);
                    return Poll::Pending;
                }
                Poll::Ready(res) => res, // Write completed
            }
        } else {
            // Try the sync flush operation first
            match std::io::Write::flush(inner) {
                Ok(()) => return Poll::Ready(Ok(())), // Nothing to flush
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Need to flush the write buffer asynchronously
                    this.write_future.replace(Box::pin(inner.flush_write_buf()));
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(e) => return Poll::Ready(Err(e)), // Other error
            }
        };

        // Convert the flush result (usize) to () for the flush operation
        Poll::Ready(res.map(|_| ()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // First ensure any pending writes are flushed
        let flush_result = self.as_mut().poll_flush(cx);
        match flush_result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                // Flush completed, proceed with shutdown
            }
        }

        let this = self.project();
        let inner: &'static mut SyncStream<S> =
            unsafe { &mut *(this.inner.get_unchecked_mut() as *mut _) };

        // Check if we have an ongoing shutdown operation
        if let Some(mut f) = this.shutdown_future.take() {
            match f.as_mut().poll(cx) {
                Poll::Pending => {
                    this.shutdown_future.replace(f);
                    return Poll::Pending;
                }
                Poll::Ready(res) => return Poll::Ready(res),
            }
        }

        // Start shutdown operation
        this.shutdown_future.replace(Box::pin(inner.shutdown()));
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UTcpStream;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use tokio_uring::net::{TcpListener, TcpStream};

    /// Test SyncStream with UTcpStream - demonstrates sync I/O with explicit buffer management
    #[test]
    fn test_sync_stream_basic() {
        tokio_uring::start(async {
            // Set up a simple echo server
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr).unwrap();
            let addr = listener.local_addr().unwrap();

            // Spawn echo server task
            tokio_uring::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut sync_stream = SyncStream::new(UTcpStream(stream));

                // Echo back data
                loop {
                    match sync_stream.fill_read_buf().await {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            // Read what was buffered
                            let mut buf = [0u8; 1024];
                            match sync_stream.read(&mut buf) {
                                Ok(n) if n > 0 => {
                                    // Write it back
                                    if sync_stream.write(&buf[..n]).is_ok() {
                                        let _ = sync_stream.flush_write_buf().await;
                                    }
                                }
                                _ => break,
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            // Connect and test
            let client_stream = TcpStream::connect(addr).await.unwrap();
            let mut sync_stream = SyncStream::new(UTcpStream(client_stream));

            // Test data
            let test_data = b"Hello, world!";

            // Write data
            let written = sync_stream.write(test_data).unwrap();
            assert_eq!(written, test_data.len());

            // Flush the write buffer
            sync_stream.flush_write_buf().await.unwrap();

            // Fill read buffer
            sync_stream.fill_read_buf().await.unwrap();

            // Read echoed data
            let mut read_buf = vec![0u8; test_data.len()];
            let read = sync_stream.read(&mut read_buf).unwrap();
            assert_eq!(read, test_data.len());
            assert_eq!(&read_buf[..read], test_data);
        });
    }

    /// Test AsyncStream with UTcpStream - demonstrates futures-util async I/O traits
    #[test]
    fn test_async_stream_basic() {
        tokio_uring::start(async {
            // Set up a simple echo server
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr).unwrap();
            let addr = listener.local_addr().unwrap();

            // Spawn echo server task
            tokio_uring::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut async_stream = AsyncStream::new(UTcpStream(stream));

                // Echo back data
                let mut buf = [0u8; 1024];
                while let Ok(n) = async_stream.read(&mut buf).await {
                    if n == 0 {
                        break; // EOF
                    }
                    async_stream.write_all(&buf[..n]).await.unwrap();
                    async_stream.flush().await.unwrap();
                }
            });

            // Connect and test
            let client_stream = TcpStream::connect(addr).await.unwrap();
            let mut async_stream = AsyncStream::new(UTcpStream(client_stream));

            // Test data
            let test_data = b"Hello from AsyncStream!";

            // Write data
            async_stream.write_all(test_data).await.unwrap();
            async_stream.flush().await.unwrap();

            // Read echoed data
            let mut read_buf = vec![0u8; test_data.len()];
            async_stream.read_exact(&mut read_buf).await.unwrap();
            assert_eq!(&read_buf, test_data);
        });
    }

    /// Test that SyncStream correctly returns WouldBlock errors when buffers need async operations
    #[test]
    fn test_sync_stream_would_block() {
        tokio_uring::start(async {
            // Test that sync operations return WouldBlock appropriately
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr).unwrap();
            let addr = listener.local_addr().unwrap();

            tokio_uring::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                // Don't do anything - just accept and hold the connection
                std::future::pending::<()>().await;
                drop(stream);
            });

            let client_stream = TcpStream::connect(addr).await.unwrap();
            let mut sync_stream = SyncStream::new(UTcpStream(client_stream));

            // Try to read from empty stream - should get WouldBlock
            let mut buf = [0u8; 10];
            match sync_stream.read(&mut buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Expected behavior
                }
                other => panic!("Expected WouldBlock, got {other:?}"),
            }

            // Write some data to fill buffer
            let test_data = b"test";
            let written = sync_stream.write(test_data).unwrap();
            assert_eq!(written, test_data.len());

            // Try to flush - should work since buffer has data
            match sync_stream.flush() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Expected - needs async flush
                }
                other => panic!("Expected WouldBlock for flush, got {other:?}"),
            }
        });
    }
}
