use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("../proto/untrusted.proto")?;
    tonic_build::compile_protos("../proto/securedexchange.proto")?;

    let is_sim = env::var("SGX_MODE").ok().as_deref() == Some("SW");

    println!(
        "cargo:rustc-cfg=SGX_MODE=\"{}\"",
        if is_sim { "SW" } else { "HW" }
    );

    Ok(())
}
