mod uipbdiauthz;
use log::{info, warn};
use protobuf::Message;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::collections::HashMap;
use std::time::Duration;
use std::sync::LazyLock;
use uipbdiauthz::{FilterRequest, FilterResponse};

// Pre-computed pseudo-header mappings to avoid format! allocations
static PSEUDO_HEADER_MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("method", "x-original-req-method"),
        ("scheme", "x-original-req-scheme"),
        ("authority", "x-original-req-authority"),
        ("path", "x-original-req-path"),
    ])
});

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(AuthEngine::new()) });
}}

struct AuthEngine {
    grpc_message: Option<String>,
    // Pre-allocate collections to avoid repeated allocations
    headers_buffer: HashMap<String, String>,
    // Cache cluster name to avoid rebuilding on each request
    cluster_name: String,
    // Track memory usage per request
    request_memory_bytes: usize,
}

impl AuthEngine {
    fn new() -> Self {
        Self {
            grpc_message: None,
            // Pre-allocate with expected capacity
            headers_buffer: HashMap::with_capacity(10),
            // Cache cluster name at initialization
            cluster_name: Self::build_cluster_name(),
            // Initialize memory tracking
            request_memory_bytes: 0,
        }
    }

    // Helper to estimate memory usage of strings and collections
    fn estimate_memory_usage(&self) -> usize {
        let mut total_bytes = 0;
        
        // Cluster name (cached, amortized over all requests)
        total_bytes += self.cluster_name.len();
        
        // Headers buffer
        for (key, value) in &self.headers_buffer {
            total_bytes += key.len() + value.len() + 48; // HashMap overhead estimate
        }
        
        // gRPC message
        if let Some(ref msg) = self.grpc_message {
            total_bytes += msg.len();
        }
        
        total_bytes
    }

    // Use string slice instead of returning reference - more efficient for empty check
    fn get_value_or_space(value: &str) -> &str {
        if value.trim().is_empty() {
            " " // Return single space for null/empty values
        } else {
            value
        }
    }

    // Optimized headers map building with pre-allocated collections and string borrowing
    fn build_protobuf_headers_map(&mut self) -> HashMap<String, String> {
        // Clear and reuse existing HashMap to avoid allocation
        self.headers_buffer.clear();

        let headers = self.get_http_request_headers();

        // Use const slice instead of Vec + HashSet for better performance
        const HEADERS_TO_SEND: &[&str] = &[
            "x-forwarded-client-cert",
            "x-request-id",
            "x-correlation-id",
            "authorization",
            "x-uip-wasm-impersonated-user",
            "x-event-service-user",
            "x-trino-user",
        ];

        for (name, value) in headers {
            // Avoid unnecessary string allocations by working with string slices where possible
            if let Some(stripped) = name.strip_prefix(':') {
                // Use pre-computed mapping - direct string insertion for known headers
                if let Some(&new_header_name) = PSEUDO_HEADER_MAP.get(stripped) {
                    info!(
                        "Converting pseudo-header '{}' to '{}' for protobuf",
                        name, new_header_name
                    );
                    // Use the pre-computed static string directly
                    self.headers_buffer.insert(new_header_name.to_owned(), value);
                } else {
                    // Fallback for unknown pseudo-headers - only allocate when necessary
                    let new_header_name = format!("x-original-req-{}", stripped);
                    info!(
                        "Converting unknown pseudo-header '{}' to '{}' for protobuf",
                        name, new_header_name
                    );
                    self.headers_buffer.insert(new_header_name, value);
                }
            } else {
                // Use more efficient contains check
                if HEADERS_TO_SEND.contains(&name.as_str()) {
                    self.headers_buffer.insert(name.clone(), value);
                    info!("Added specific header to protobuf: '{}'", name);
                } else {
                    info!("Skipping non-specific header '{}' in protobuf", name);
                }
            }
        }

        info!(
            "Built protobuf headers map with {} entries",
            self.headers_buffer.len()
        );
        
        // Return ownership to avoid cloning in protobuf insertion
        std::mem::take(&mut self.headers_buffer)
    }

    // Extract common gRPC call logic to reduce code duplication
    fn make_grpc_call(&self, cluster_name: &str, message: &[u8]) -> Result<u32, Status> {
        let grpc_headers: &[(&str, &[u8])] = &[("from-proxy-wasm-pdk", b"proxy")];

        // Log gRPC metadata headers
        info!("[GRPC-HEADERS] gRPC metadata headers ({} total):", grpc_headers.len());
        for (key, value) in grpc_headers {
            info!("[GRPC-HEADERS]   '{}' = '{}'", key, String::from_utf8_lossy(value));
        }

        self.dispatch_grpc_call(
            cluster_name,
            "authengine.UIPBDIAuthZProcessor",
            "processReq",
            grpc_headers.to_vec(),
            Some(message),
            Duration::from_secs(5),
        )
    }

    // Build cluster name once at initialization
    fn build_cluster_name() -> String {
        let service_instance =
            std::env::var("SERVICE_INSTANCE").unwrap_or_else(|_| "localhost".into());
        format!(
            "outbound|50051||{}.localhost.for.grpc.call",
            service_instance
        )
    }
}

impl HttpContext for AuthEngine {
    fn on_http_request_headers(&mut self, _: usize, _end_of_stream: bool) -> Action {
        info!("Entering on_http_request_headers");
        info!("Initializing gRPC OAuth 2.0 policy");
        
        // Reset and track memory for this request
        self.request_memory_bytes = 0;
        let initial_memory = self.estimate_memory_usage();
        info!("[MEMORY] Initial memory usage: {} bytes", initial_memory);

        // Get headers for logging - use as_deref to get &str for display
        let method_opt = self.get_http_request_header(":method");
        let scheme_opt = self.get_http_request_header(":scheme");
        let authority_opt = self.get_http_request_header(":authority");
        let path_opt = self.get_http_request_header(":path");

        info!(
            "Request details - Method: {}, Scheme: {}, Authority: {}, Path: {}",
            method_opt.as_deref().unwrap_or(""),
            scheme_opt.as_deref().unwrap_or(""),
            authority_opt.as_deref().unwrap_or(""),
            path_opt.as_deref().unwrap_or("")
        );

        // Build headers map for protobuf (takes ownership to avoid clones)
        let headers_map = self.build_protobuf_headers_map();
        let after_headers_memory = self.estimate_memory_usage();
        info!("[MEMORY] After header processing: {} bytes (+{} bytes)", 
              after_headers_memory, after_headers_memory - initial_memory);

        // Log all headers that will be sent in the protobuf message
        info!("[HEADERS] Headers to be sent in gRPC call ({} total):", headers_map.len());
        for (key, value) in &headers_map {
            info!("[HEADERS]   '{}' = '{}'", key, value);
        }

        // Create FilterRequest
        let mut req = FilterRequest::new();
        // Insert headers by taking ownership - no clones needed!
        *req.mut_headers() = headers_map;
        
        // Set protobuf fields - use unwrap_or_default for String types (minimal allocation for empty strings)
        req.set_method(method_opt.unwrap_or_default());
        req.set_path(path_opt.unwrap_or_default());
        req.set_scheme(scheme_opt.unwrap_or_default());

        let message = match req.write_to_bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to serialize request: {:?}", e);
                return Action::Continue;
            }
        };

        info!(
            "Constructed FilterRequest with {} protobuf headers, message size: {} bytes",
            req.get_headers().len(),
            message.len()
        );

        // Use cached cluster name
        info!("[DEBUG] Using cached cluster name: {}", self.cluster_name);

        match self.make_grpc_call(&self.cluster_name, &message) {
            Ok(token) => {
                info!("Successfully dispatched gRPC call with token: {}", token);
                Action::Pause
            }
            Err(e) => {
                warn!("Failed to dispatch gRPC call: {:?}", e);
                Action::Continue
            }
        }
    }

    fn on_http_response_headers(&mut self, _: usize, _end_of_stream: bool) -> Action {
        if let Some(message) = &self.grpc_message {
            info!("Setting response headers with message: {}", message);
            self.set_http_response_header("x-filter-response-pdk-response", Some(message));
        }
        Action::Continue
    }
}

impl Context for AuthEngine {
    fn on_grpc_call_response(&mut self, token_id: u32, status_code: u32, response_size: usize) {
        info!(
            "gRPC response received - Token: {}, Status: {}, Size: {}",
            token_id, status_code, response_size
        );

        let Some(response_data) = self.get_grpc_call_response_body(0, response_size) else {
            warn!("No response data received from auth service");
            self.send_http_response(500, vec![], Some(b"Internal Server Error"));
            return;
        };

        info!(
            "Received raw response data of size: {}",
            response_data.len()
        );

        let reply = match FilterResponse::parse_from_bytes(&response_data) {
            Ok(reply) => reply,
            Err(e) => {
                warn!("Failed to parse gRPC response: {:?}", e);
                if let Ok(raw_str) = String::from_utf8(response_data) {
                    warn!("Raw response content: {}", raw_str);
                }
                self.send_http_response(500, vec![], Some(b"Internal Server Error"));
                return;
            }
        };

        let response_message = reply.get_message();
        info!(
            "Successfully parsed filter service response: {}",
            response_message
        );

        // Check if access is denied
        if !reply.get_allow() {
            info!("Access denied: allow=false, message={}", response_message);
            self.send_http_response(
                401,
                vec![("WWW-Authenticate", response_message)], // Avoid string allocation
                Some(b"Unauthorized"),
            );
            return;
        }

        // Use the optimized helper function
        let user = Self::get_value_or_space(reply.get_user());
        self.add_http_request_header("x-uip-user", user);
        info!("Set user header: '{}'", user);

        // Store the response message for later use - only convert to String when storing
        self.grpc_message = Some(response_message.to_string());

        // Calculate final memory usage for this request
        let final_memory = self.estimate_memory_usage();
        let total_request_memory = final_memory; // Approximate total for this request
        
        info!(
            "[MEMORY] Final memory usage: {} bytes, total request memory: ~{} bytes",
            final_memory, total_request_memory
        );

        info!(
            "Resuming request with {} headers",
            self.get_http_request_headers().len()
        );

        // Resume the request
        self.resume_http_request();
    }
}
