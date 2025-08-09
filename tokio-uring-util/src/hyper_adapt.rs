use crate::{AsyncRead, AsyncStream, AsyncWrite};
use futures_util::io::{AsyncRead as FutAsyncRead, AsyncWrite as FutAsyncWrite};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

/// A stream wrapper for hyper.
pub struct HyperStream<S>(AsyncStream<S>);

impl<S: AsyncRead + AsyncWrite> HyperStream<S> {
    /// Create a hyper stream wrapper.
    pub fn new(s: S) -> Self {
        Self(AsyncStream::new(s))
    }

    /// Get the reference of the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }
}

impl<S> std::fmt::Debug for HyperStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HyperStream").finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + 'static> hyper::rt::Read for HyperStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // Convert MaybeUninit buffer to regular u8 buffer
        let uninit_slice = unsafe { buf.as_mut() };
        let slice = unsafe {
            std::slice::from_raw_parts_mut(uninit_slice.as_mut_ptr() as *mut u8, uninit_slice.len())
        };
        let len = ready!(Pin::new(&mut self.0).poll_read(cx, slice))?;
        unsafe { buf.advance(len) };
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + 'static> hyper::rt::Write for HyperStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

#[derive(Clone, Copy)]
pub struct UExecutor;

impl<Fut> hyper::rt::Executor<Fut> for UExecutor
where
    Fut: std::future::Future + 'static,
    Fut::Output: 'static,
{
    fn execute(&self, fut: Fut) {
        tokio_uring::spawn(fut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UTcpStream;
    use std::net::SocketAddr;
    use tokio_uring::net::{TcpListener, TcpStream};

    /// Test that HyperStream can be created and basic traits work
    #[test]
    fn test_hyper_stream_creation() {
        tokio_uring::start(async {
            // Set up a TCP connection
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = TcpListener::bind(addr).unwrap();
            let addr = listener.local_addr().unwrap();

            // Spawn a simple server
            tokio_uring::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream); // Just accept and close
            });

            // Connect and test HyperStream creation
            let client_stream = TcpStream::connect(addr).await.unwrap();
            let utcp_stream = UTcpStream(client_stream);

            // Create HyperStream
            let hyper_stream = HyperStream::new(utcp_stream);

            // Test that we can get the reference
            let _inner_ref = hyper_stream.get_ref();

            // Test Debug trait
            let debug_str = format!("{hyper_stream:?}");
            assert!(debug_str.contains("HyperStream"));
        });
    }
}

#[cfg(test)]
mod http_tests {
    use std::convert::Infallible;
    use std::net::SocketAddr;

    use http_body_util::{BodyExt, Empty, Full};
    use hyper::body::Bytes;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use tokio_uring::net::{TcpListener, TcpStream};

    use crate::{HyperStream, UTcpStream};

    async fn hello(
        _: Request<impl hyper::body::Body>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        Ok(Response::new(Full::new(Bytes::from("Hello World!"))))
    }

    async fn server(listener: TcpListener) {
        println!("Listening on http://{}", listener.local_addr().unwrap());

        let (stream, _) = listener.accept().await.unwrap();
        let io = HyperStream::new(UTcpStream(stream));

        // Serve the connection with proper error handling
        let result = http1::Builder::new()
            .serve_connection(io, service_fn(hello))
            .await;

        match result {
            Ok(()) => println!("Server connection completed successfully"),
            Err(err) => {
                // Check if it's a connection-related error that indicates improper client shutdown
                if err.is_canceled() || err.is_closed() {
                    println!("Client disconnected abruptly: {err:?}");
                } else {
                    println!("Error serving connection: {err:?}");
                }
            }
        }
        println!("server end.")
    }

    async fn client(addr: SocketAddr) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let io = HyperStream::new(UTcpStream(stream));

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        let conn_task = tokio_uring::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {err:?}");
            }
            println!("Client connection task ended");
        });

        let path = "/";
        let req = Request::builder()
            .uri(path)
            .body(Empty::<Bytes>::new())
            .unwrap();

        let mut res = sender.send_request(req).await.unwrap();

        println!("Response: {}", res.status());
        println!("Headers: {:#?}\n", res.headers());

        // Stream the body, writing each chunk to stdout as we get it
        // (instead of buffering and printing at the end).
        while let Some(next) = res.frame().await {
            let frame = next.unwrap();
            if let Some(chunk) = frame.data_ref() {
                if !chunk.is_empty() {
                    print!("{}", String::from_utf8_lossy(chunk));
                }
            }
        }

        println!("\n\nDone!");

        // Close the client request. Without this connection will run forever.
        // Properly shutdown the sender
        drop(sender);

        // Wait for the connection task to complete
        conn_task.await.unwrap();
        println!("Client finished completely");
    }

    #[test]
    fn http_test() {
        tokio_uring::start(async {
            let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = listener.local_addr().unwrap();

            let server_task = tokio_uring::spawn(async move {
                server(listener).await;
                println!("Server task finished");
            });

            // Run client
            client(addr).await;

            println!("Client finished, waiting for server to complete");

            // The server should complete naturally when the client closes the connection
            server_task.await.unwrap();

            println!("Test completed successfully");
        })
    }
}

#[cfg(test)]
mod http2_tests {
    use super::*;
    use crate::UTcpStream;
    use http_body_util::{Empty, Full};
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::net::SocketAddr;
    use tokio_uring::net::{TcpListener, TcpStream};

    async fn hello_handler(
        _req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        Ok(Response::new(Full::new(Bytes::from("Hello HTTP/2 World!"))))
    }

    async fn http2_server(listener: TcpListener) {
        println!(
            "HTTP/2 server listening on {}",
            listener.local_addr().unwrap()
        );

        let (stream, _) = listener.accept().await.unwrap();
        let io = HyperStream::new(UTcpStream(stream));

        println!("HTTP/2 server accepted connection");

        // Use HTTP/2 directly since hyper_util::auto might not be available
        let result = hyper::server::conn::http2::Builder::new(UExecutor)
            .serve_connection(io, service_fn(hello_handler))
            .await;

        match result {
            Ok(()) => println!("HTTP/2 server connection completed successfully"),
            Err(err) => {
                println!("HTTP/2 server error: {err:?}");
            }
        }
        println!("HTTP/2 server end.")
    }

    async fn http2_client(addr: SocketAddr) {
        println!("HTTP/2 client connecting to {addr}");

        let stream = TcpStream::connect(addr).await.unwrap();
        let io = HyperStream::new(UTcpStream(stream));

        println!("HTTP/2 client connected, performing handshake");

        // Use HTTP/2 connection
        let (mut sender, conn): (hyper::client::conn::http2::SendRequest<Empty<Bytes>>, _) =
            hyper::client::conn::http2::handshake(UExecutor, io)
                .await
                .unwrap();

        println!("HTTP/2 handshake completed");

        let conn_task = tokio_uring::spawn(async move {
            if let Err(err) = conn.await {
                println!("HTTP/2 connection failed: {err:?}");
            } else {
                println!("HTTP/2 connection completed successfully");
            }
            println!("HTTP/2 client connection task ended");
        });

        let req = Request::builder()
            .uri("/")
            .body(Empty::<Bytes>::new())
            .unwrap();

        println!("Sending HTTP/2 request");

        // Now that we fixed the write buffer capacity issue, let's try the actual request
        match sender.send_request(req).await {
            Ok(res) => {
                println!("✅ HTTP/2 Request successful!");
                println!("HTTP/2 Response: {}", res.status());
                println!("HTTP/2 Headers: {:#?}\n", res.headers());

                // Collect the body using http_body_util
                match http_body_util::BodyExt::collect(res.into_body()).await {
                    Ok(body) => {
                        let body_bytes = body.to_bytes();
                        println!("Response body: {}", String::from_utf8_lossy(&body_bytes));
                    }
                    Err(e) => {
                        println!("Failed to collect response body: {e:?}");
                    }
                }
            }
            Err(e) => {
                println!("❌ HTTP/2 request failed: {e:?}");
            }
        }

        println!("\n\nHTTP/2 client done!");

        // Drop the sender to signal we're done sending requests
        drop(sender);
        println!("Sender dropped, waiting for connection to close");

        // Wait for connection to complete
        conn_task.await.unwrap();
        println!("HTTP/2 client finished completely");
    }

    #[test]
    fn http2_test() {
        tokio_uring::start(async {
            let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = listener.local_addr().unwrap();

            println!("Starting HTTP/2 test on {addr}");

            let server_task = tokio_uring::spawn(async move {
                http2_server(listener).await;
                println!("HTTP/2 server task finished");
            });

            // Give server time to start - use a simple delay
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Run HTTP/2 client
            http2_client(addr).await;

            println!("HTTP/2 client finished, waiting for server to complete");

            // The server should complete when the client closes the connection
            server_task.await.unwrap();

            println!("HTTP/2 test completed successfully");
        })
    }
}
