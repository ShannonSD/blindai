// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use blindai_sgx::start_server;

use std::{
    collections::hash_map::DefaultHasher,
    ffi::CString,
    hash::{Hash, Hasher},
    thread,
};

use blindai_common::fake_local_app_server;
use env_logger::Env;
use log::info;

use std::{fs::File, io::Read};

use tonic::transport::Server;

use anyhow::Result;

#[derive(Default)]
pub struct State {}

#[tonic::async_trait]
impl fake_local_app_server::FakeLocalApp for State {
    async fn setup_app(
        &self,
        _request: tonic::Request<Vec<u8>>,
    ) -> Result<tonic::Response<String>, tonic::Status> {
        Ok(tonic::Response::new(String::from("hello")))
    }
}
fn fill_blank_and_print(content: &str, size: usize) {
    let trail_char = "#";
    let trail: String = trail_char.repeat((size - 2 - content.len()) / 2);
    let trail2: String =
        trail_char.repeat(((size - 2 - content.len()) as f32 / 2.0).ceil() as usize);
    println!("{} {} {}", trail, content, trail2);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let logo_str: &str = include_str!("../logo.txt");
    let version_str: String = format!("VERSION : {}", env!("CARGO_PKG_VERSION"));
    let text_size: usize = 58;
    println!("{}\n", logo_str);
    fill_blank_and_print("BlindAI - INFERENCE SERVER", text_size);
    fill_blank_and_print("MADE BY MITHRIL SECURITY", text_size);
    fill_blank_and_print(
        "GITHUB: https://github.com/mithril-security/blindai",
        text_size,
    );
    fill_blank_and_print(&version_str, text_size);
    println!();
    info!("Starting Enclave...");

    let mut file = File::open("/opt/blindai/config.toml")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let network_config: blindai_common::NetworkConfig = toml::from_str(&contents)?;

    info!(
        "Starting server for Enclave --> Host internal communication at {}",
        network_config.internal_enclave_to_host_url
    );
    tokio::spawn(
        Server::builder()
            .add_service(fake_local_app_server::FakeLocalAppServer::new(State {}))
            .serve(network_config.internal_enclave_to_host_socket()?),
    );

    let platform: CString = CString::new(format!("{} - SGX {}", whoami::platform(), "SW")).unwrap();
    let uid: CString = {
        let mut hasher = DefaultHasher::new();
        whoami::username().hash(&mut hasher);
        whoami::hostname().hash(&mut hasher);
        platform.hash(&mut hasher);
        CString::new(format!("{:X}", hasher.finish())).unwrap()
    };

    let _result = thread::spawn(|| {
        unsafe { start_server(platform.into_raw(), uid.into_raw()) };
    })
    .join()
    .expect("Thread panicked");

    info!("Outside start_server");

    info!("[+] start_server success...");
    Ok(())
}
