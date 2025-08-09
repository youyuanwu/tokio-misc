use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_uring::net::TcpStream;
use tokio_uring_util::{HyperStream, UTcpStream};
use tower::Service;

// Re-export useful types from tokio-uring-util for convenience
pub use tokio_uring_util::UExecutor;

/// A boxed future that implements Send for use with tonic
pub struct SendableUringFuture {
    inner: Pin<Box<dyn Future<Output = Result<UringConnection, std::io::Error>>>>,
}

impl SendableUringFuture {
    fn new<F>(future: F) -> Self
    where
        F: Future<Output = Result<UringConnection, std::io::Error>> + 'static,
    {
        Self {
            inner: Box::pin(future),
        }
    }
}

// Safety: We're using tokio-uring in single-threaded mode, so Send is safe
unsafe impl Send for SendableUringFuture {}

impl Future for SendableUringFuture {
    type Output = Result<UringConnection, std::io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

/// Create a new connector service using tower::service_fn for tokio-uring gRPC clients.
///
/// This function creates a tower::Service that can properly handle async connections
/// within the tokio-uring runtime.
pub fn create_uring_connector() -> impl Service<
    hyper::Uri,
    Response = UringConnection,
    Error = std::io::Error,
    Future = SendableUringFuture,
> + Clone {
    tower::service_fn(|uri: hyper::Uri| {
        let future = async move {
            let host = uri.host().unwrap_or("localhost");
            let port = uri.port_u16().unwrap_or(50051); // Default gRPC port

            println!("UringConnector: Connecting to {host}:{port}");

            // We can use await here since we're in an async closure!
            let addr: SocketAddr = format!("{host}:{port}")
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            println!("UringConnector: Parsed address: {addr}");

            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    println!("UringConnector: Successfully connected!");
                    Ok(UringConnection::new(stream))
                }
                Err(e) => {
                    println!("UringConnector: Connection failed: {e}");
                    Err(e)
                }
            }
        };

        SendableUringFuture::new(future)
    })
}

/// A connection type that wraps our tokio-uring stream for use with hyper/tonic
pub struct UringConnection {
    inner: HyperStream<UTcpStream>,
}

impl UringConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            inner: HyperStream::new(UTcpStream(stream)),
        }
    }
}

// Safety: We're using tokio-uring in single-threaded mode, so Send is safe
unsafe impl Send for UringConnection {}

impl hyper::rt::Read for UringConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UringConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Helper function to create a UringConnection directly
///
/// Since tokio-uring has threading constraints, this function should be used
/// within the tokio-uring runtime to create connections.
pub async fn connect_to(addr: SocketAddr) -> Result<UringConnection, std::io::Error> {
    let stream = TcpStream::connect(addr).await?;
    Ok(UringConnection::new(stream))
}

/// Helper function to create a UringConnection to a host:port
pub async fn connect(host: &str, port: u16) -> Result<UringConnection, std::io::Error> {
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    connect_to(addr).await
}

/// Example usage with a hypothetical gRPC service
///
/// ```no_run
/// use tonic_uring::{connect, UringConnection};
///
/// // This would be your generated gRPC client
/// // use my_service::my_service_client::MyServiceClient;
///
/// fn example_usage() -> Result<(), Box<dyn std::error::Error>> {
///     tokio_uring::start(async {
///         // Connect to gRPC server using tokio-uring
///         let connection = connect("localhost", 50051).await?;
///         
///         // You would create a hyper client with this connection
///         // and then use it with tonic manually, since tonic's
///         // Channel::builder().connector() is not public
///         
///         // For now, the connection can be used directly with hyper
///         println!("Connected successfully!");
///         
///         Ok::<(), Box<dyn std::error::Error>>(())
///     })
/// }
/// ```
pub fn _example_function() {
    // This function exists only to attach the documentation example to
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_helpers() {
        tokio_uring::start(async {
            // Test parsing invalid address
            let result = connect("invalid_host", 8080);
            // Should fail to connect to non-existent host
            assert!(result.await.is_err());
        });
    }
}
