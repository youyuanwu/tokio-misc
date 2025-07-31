use tonic::{Request, Response, Status};

use crate::helloworld::{HelloReply, HelloRequest};

#[cfg(test)]
pub mod openssl;
#[cfg(test)]
pub mod utils;

pub mod helloworld {
    tonic::include_proto!("helloworld");
}

pub struct MyGreeter;

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request from {:?}", request.remote_addr());

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;

    use super::*;

    fn run_server(token: CancellationToken) -> std::thread::JoinHandle<()> {
        std::thread::spawn(|| {
            tokio_uring::start(async move {
                let addr = "[::1]:50051".parse().unwrap();
                let greeter = MyGreeter;

                tonic::transport::Server::builder()
                    .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
                    .serve_with_shutdown(addr, token.cancelled())
                    .await
                    .unwrap();
            });
        })
    }

    // This passes but is not using uring, because there is a current thread runtime behind the uring start.
    #[test]
    fn test_greeter() {
        let token = CancellationToken::new();
        let server_handle = run_server(token.clone());

        // Allow some time for the server to start
        std::thread::sleep(std::time::Duration::from_secs(1));

        tokio_uring::start(async move {
            let mut client =
                helloworld::greeter_client::GreeterClient::connect("http://[::1]:50051")
                    .await
                    .unwrap();

            let request = tonic::Request::new(HelloRequest {
                name: "World".into(),
            });

            let response = client.say_hello(request).await.unwrap();
            assert_eq!(response.into_inner().message, "Hello World!");
        });

        token.cancel();
        server_handle.join().unwrap();
    }
}
