use protobuf_codegen_pure::Customize;

fn main() {
    protobuf_codegen_pure::Codegen::new()
        .customize(Customize {
            lite_runtime: Some(true),
            ..Default::default()
        })
        .out_dir("src")
        .inputs(&[
            "../../proto/Frpg2RequestMessage.proto",
            "../../proto/dks3/common.proto",
        ])
        .include("../../proto")
        .run()
        .expect("protoc");
}
