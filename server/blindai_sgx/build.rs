fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../proto/untrusted.proto");
    println!("cargo:rerun-if-changed=../proto/securedexchange.proto");
    tonic_build::compile_protos("../proto/securedexchange.proto")?;
    tonic_build::compile_protos("../proto/untrusted.proto")?;

    println!("cargo:rustc-cfg=SGX_MODE=\"SW\"");
    Ok(())
}
