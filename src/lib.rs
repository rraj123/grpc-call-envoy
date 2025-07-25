mod uipbdiauthz;
use log::{info, warn};
use protobuf::Message;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use std::collections::HashMap;
use std::time::Duration;
use uipbdiauthz::{FilterRequest, FilterResponse};

// Memory tracking for leak detection (only when feature is enabled)
#[cfg(feature = "memory-tracking")]
use stats_alloc::{StatsAlloc, INSTRUMENTED_SYSTEM};
#[cfg(feature = "memory-tracking")]
use std::alloc::System;

#[cfg(feature = "memory-tracking")]
#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// Pre-computed pseudo-header mappings as fixed array - no heap allocation
const PSEUDO_HEADER_MAP: [(&str, &str); 4] = [
    ("method", "x-original-req-method"),
    ("scheme", "x-original-req-scheme"),
    ("authority", "x-original-req-authority"),
    ("path", "x-original-req-path"),
];

// Memory tracking utilities
#[cfg(feature = "memory-tracking")]
mod memory_tracking {
    use super::*;
    use stats_alloc::{Stats, INSTRUMENTED_SYSTEM};

    pub fn get_memory_stats() -> Stats {
        INSTRUMENTED_SYSTEM.stats()
    }

    pub fn log_memory_change(stage: &str, before: Option<Stats>) {
        let current = get_memory_stats();
        
        if let Some(before) = before {
            let bytes_delta = current.bytes_allocated as i64 - before.bytes_allocated as i64;
            let allocs_delta = current.allocations as i64 - before.allocations as i64;
            let deallocs_delta = current.deallocations as i64 - before.deallocations as i64;
            
            info!(
                "[MEMORY-TRACK] {}: bytes_allocated={} ({:+}), allocations={} ({:+}), deallocations={} ({:+}), leaked_bytes={}",
                stage,
                current.bytes_allocated, 
                bytes_delta,
                current.allocations,
                allocs_delta,
                current.deallocations,
                deallocs_delta,
                current.bytes_allocated as i64 - current.deallocations as i64
            );
        } else {
            info!(
                "[MEMORY-TRACK] {}: bytes_allocated={}, allocations={}, deallocations={}",
                stage,
                current.bytes_allocated,
                current.allocations,
                current.deallocations
            );
        }
    }

    pub fn detect_memory_leak(stage: &str, before: Stats) {
        let current = get_memory_stats();
        let net_allocations = (current.allocations - current.deallocations) as i64 
                            - (before.allocations - before.deallocations) as i64;
        
        if net_allocations > 0 {
            warn!(
                "[MEMORY-LEAK] Potential leak at {}: {} net allocations, {} bytes potentially leaked",
                stage,
                net_allocations,
                current.bytes_allocated as i64 - before.bytes_allocated as i64
            );
        }
    }
}

#[cfg(not(feature = "memory-tracking"))]
mod memory_tracking {
    #[derive(Clone, Copy)]
    pub struct Stats {
        pub bytes_allocated: usize,
        pub allocations: usize,
        pub deallocations: usize,
    }
    
    pub fn get_memory_stats() -> Stats {
        Stats { bytes_allocated: 0, allocations: 0, deallocations: 0 }
    }
    
    pub fn log_memory_change(_stage: &str, _before: Option<Stats>) {}
    pub fn detect_memory_leak(_stage: &str, _before: Stats) {}
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_http_context(|_, _| -> Box<dyn HttpContext> { Box::new(AuthEngine::new()) });
}}

struct AuthEngine {
    // Pre-allocate collections to avoid repeated allocations
    headers_buffer: HashMap<String, String>,
    // Cache cluster name to avoid rebuilding on each request
    cluster_name: String,
    // Track memory usage per request
    request_memory_bytes: usize,
    // Memory tracking baseline for leak detection
    #[cfg(feature = "memory-tracking")]
    request_start_stats: Option<stats_alloc::Stats>,
}

impl AuthEngine {
    fn new() -> Self {
        // Log plugin initialization memory state
        memory_tracking::log_memory_change("Plugin Initialization", None);
        
        Self {
            // Pre-allocate with expected capacity
            headers_buffer: HashMap::with_capacity(10),
            // Cache cluster name at initialization
            cluster_name: Self::build_cluster_name(),
            // Initialize memory tracking
            request_memory_bytes: 0,
            // Initialize memory tracking baseline
            #[cfg(feature = "memory-tracking")]
            request_start_stats: None,
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

    // Optimized headers map building - build final HashMap directly
    fn build_protobuf_headers_map(&mut self) -> HashMap<String, String> {
        // Build HashMap directly with pre-allocated capacity instead of using buffer
        let mut headers_map = HashMap::with_capacity(11); // 4 pseudo + 7 regular headers max

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

        // Process specific pseudo-headers individually to avoid Vec allocation
        // Use const array to avoid format! allocations
        const PSEUDO_HEADERS: [(&str, &str); 4] = [
            (":method", "method"),
            (":scheme", "scheme"),
            (":authority", "authority"),
            (":path", "path"),
        ];

        for &(header_name, pseudo_key) in &PSEUDO_HEADERS {
            if let Some(value) = self.get_http_request_header(header_name) {
                if let Some((_, new_header_name)) =
                    PSEUDO_HEADER_MAP.iter().find(|(key, _)| *key == pseudo_key)
                {
                    info!(
                        "Converting pseudo-header '{}' to '{}' for protobuf",
                        header_name, new_header_name
                    );
                    headers_map.insert(new_header_name.to_string(), value);
                }
            }
        }

        // Then handle specific headers we want to forward
        for &header_name in HEADERS_TO_SEND {
            if let Some(value) = self.get_http_request_header(header_name) {
                headers_map.insert(header_name.to_string(), value);
                info!("Added specific header to protobuf: '{}'", header_name);
            }
        }

        info!(
            "Built protobuf headers map with {} entries",
            headers_map.len()
        );

        headers_map
    }

    // Extract common gRPC call logic to reduce code duplication
    fn make_grpc_call(&self, cluster_name: &str, message: &[u8]) -> Result<u32, Status> {
        self.dispatch_grpc_call(
            cluster_name,
            "authengine.UIPBDIAuthZProcessor",
            "processReq",
            vec![],
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

        // Initialize memory tracking for this request
        #[cfg(feature = "memory-tracking")]
        {
            self.request_start_stats = Some(memory_tracking::get_memory_stats());
            memory_tracking::log_memory_change("Request Start", None);
        }

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
        info!(
            "[MEMORY] After header processing: {} bytes (+{} bytes)",
            after_headers_memory,
            after_headers_memory - initial_memory
        );

        // Track memory after header processing
        #[cfg(feature = "memory-tracking")]
        memory_tracking::log_memory_change("After Header Processing", self.request_start_stats);

        // Log all headers that will be sent in the protobuf message
        info!(
            "[HEADERS] Headers to be sent in gRPC call ({} total):",
            headers_map.len()
        );
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

        // Track memory after protobuf creation
        #[cfg(feature = "memory-tracking")]
        memory_tracking::log_memory_change("After Protobuf Creation", self.request_start_stats);

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
        // Response header is now set directly in on_grpc_call_response to avoid string storage
        Action::Continue
    }
}

impl Context for AuthEngine {
    fn on_grpc_call_response(&mut self, token_id: u32, status_code: u32, response_size: usize) {
        info!(
            "gRPC response received - Token: {}, Status: {}, Size: {}",
            token_id, status_code, response_size
        );

        // Track memory at start of gRPC response processing
        #[cfg(feature = "memory-tracking")]
        memory_tracking::log_memory_change("gRPC Response Start", self.request_start_stats);

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

        // Set response header immediately to avoid storing the message
        // Note: This bypasses on_http_response_headers() but achieves the same result
        self.set_http_response_header("x-filter-response-pdk-response", Some(response_message));

        // Calculate final memory usage for this request
        let final_memory = self.estimate_memory_usage();
        let total_request_memory = final_memory; // Approximate total for this request

        info!(
            "[MEMORY] Final memory usage: {} bytes, total request memory: ~{} bytes",
            final_memory, total_request_memory
        );

        info!("Resuming request processing");

        // Track memory and detect leaks at end of request processing
        #[cfg(feature = "memory-tracking")]
        {
            memory_tracking::log_memory_change("Request End", self.request_start_stats);
            if let Some(start_stats) = self.request_start_stats {
                memory_tracking::detect_memory_leak("Request Complete", start_stats);
            }
        }

        // Resume the request
        self.resume_http_request();
    }
}
