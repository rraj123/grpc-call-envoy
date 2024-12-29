## Proxy-Wasm plugin - Test with Kind 

Proxy-Wasm plugin that logs HTTP Call out (Dispatch call) request/response headers.

### Building

```sh
cargo init --lib grpc-call-envoy  

$ cargo build --target wasm32-wasip1 --release

func-e run -c config-grpc-call.yaml (If you have func-e tool)

-- 
The other option is to run with the docker-compose (TODO)

--
docker build -t localhost:5001/wasm:v5http . --push

Go to /Users/rajramalingam/k8s-workout/Networking-and-Kubernetes/istio-1.24.1/wasm-extension 
apply-- wasm-plugin4.yaml


```
![Alt text]( output.png "Output")