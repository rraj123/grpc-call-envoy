fn main() {
    let proto_files = vec!["./protos/helloworld.proto"];

    protoc_rust::Codegen::new()
        .out_dir("./src")
        .inputs(proto_files)
        .run()
        .expect("running protoc failed");
}