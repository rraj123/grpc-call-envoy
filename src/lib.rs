mod helloworld;

use helloworld::{HelloReply, HelloRequest};
use log::{trace, warn};
use protobuf::Message;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::time::Duration;

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(GrpcCallTest::new()) });
}

struct GrpcCallTest {
    grpc_message: Option<String>,
}

impl GrpcCallTest {
    fn new() -> Self {
        Self { grpc_message: None }
    }
}

impl HttpContext for GrpcCallTest {
    fn on_http_request_headers(&mut self, _: usize, _end_of_stream: bool) -> Action {
        let mut req = HelloRequest::new();
        req.set_name("John Smith".to_string());
        let message = req.write_to_bytes().unwrap();

        match self.dispatch_grpc_call(
            "test",
            "helloworld.Greeter",
            "SayHello",
            Vec::<(&str, &[u8])>::new(),
            Some(message.as_slice()),
            Duration::from_secs(5),
        ) {
            Ok(_) => trace!("success"),
            Err(e) => trace!("Failed {:?}", e),
        }

        Action::Pause
    }

    fn on_http_response_headers(&mut self, _: usize, _end_of_stream: bool) -> Action {
        self.set_http_response_header("Powered-By", Some("proxy-wasm"));

        // Add the gRPC message to response headers if available
        if let Some(message) = &self.grpc_message {
            self.set_http_response_header("grpc-message", Some(message));
            trace!("Added gRPC message to response headers: {}", message);
        }

        Action::Continue
    }
}

impl Context for GrpcCallTest {
    fn on_grpc_call_response(&mut self, _token_id: u32, status_code: u32, response_size: usize) {
        warn!(
            "gRPC response received - Status: {}, Size: {}",
            status_code, response_size
        );

        // Get the response body
        if let Some(response_data) = self.get_grpc_call_response_body(0, response_size) {
            // Try to parse the HelloReply message
            match HelloReply::parse_from_bytes(&response_data) {
                Ok(reply) => {
                    let message = reply.get_message().to_string();
                    warn!("Received message: {}", message);
                    self.grpc_message = Some(message);
                }
                Err(e) => warn!("Failed to parse gRPC response: {:?}", e),
            }
        } else {
            warn!("No response data received");
        }

        self.resume_http_request()
    }
}
