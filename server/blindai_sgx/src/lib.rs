// Copyright 2022 Mithril Security. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![crate_name = "blindai_sgx"]
#![crate_type = "staticlib"]
#![feature(once_cell)]

#[cfg(target_env = "sgx")]
use std::backtrace::{self, PrintFormat};
use std::{ffi::CStr, os::raw::c_char, sync::Arc};

use log::*;
use std::io::Read;
use tonic::transport::ServerTlsConfig;

use tonic::transport::{Identity, Server};

#[cfg(target_env = "sgx")]
use std::untrusted::fs::File;

#[cfg(not(target_env = "sgx"))]
use std::fs::File;

#[cfg(target_env = "sgx")]
use std::untrusted::fs;

use anyhow::{Context, Result};

#[cfg(not(target_env = "sgx"))]
use std::fs;

use crate::client_communication::{secured_exchange::exchange_server::ExchangeServer, Exchanger};

use crate::{
    dcap_quote_provider::DcapQuoteProvider, model_store::ModelStore, telemetry::TelemetryEventProps,
};

use untrusted::MyAttestation;

use identity::MyIdentity;

mod client_communication;
mod dcap_quote_provider;
mod identity;
mod model;
mod model_store;
mod telemetry;
mod untrusted;

pub unsafe fn start_server(telemetry_platform: *const c_char, telemetry_uid: *const c_char) -> i32 {
    //#[cfg(target_env = "sgx")]
    //let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full);
    info!("Reached library start_server function");
    //env_logger::Builder::from_env(Env::default().default_filter_or("info")).
    // init();

    info!("Switched to enclave context");

    let telemetry_platform = CStr::from_ptr(telemetry_platform);
    let telemetry_uid = CStr::from_ptr(telemetry_uid);

    let telemetry_platform = telemetry_platform.to_owned().into_string().unwrap();
    let telemetry_uid = telemetry_uid.to_owned().into_string().unwrap();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(main(telemetry_platform, telemetry_uid))
        .unwrap();

    return 1;
}
pub unsafe extern "C" fn test_print() {
    println!("Test function called.");
}

async fn main(telemetry_platform: String, telemetry_uid: String) -> Result<()> {
    //#[cfg(target_env = "sgx")]
    //let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full);
    info!("Inside lib main!");
    let (certificate, storage_identity, signing_key_seed) =
        identity::create_certificate().context("Creating certificate")?;
    let my_identity = Arc::new(MyIdentity::from_cert(
        certificate,
        storage_identity,
        signing_key_seed,
    ));
    let enclave_identity = my_identity.tls_identity.clone();

    info!("Inside lib ddmain!");
    // Read network config into network_config
    let mut file = File::open("/opt/blindai/config.toml").context("Reading config.toml")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .context("Reading config.toml file.")?;
    let network_config: blindai_common::NetworkConfig = toml::from_str(&contents)?;

    info!("Insddide lib main!");
    let dcap_quote_provider = DcapQuoteProvider::new(&enclave_identity.cert_der);
    let dcap_quote_provider: &'static DcapQuoteProvider = Box::leak(Box::new(dcap_quote_provider));

    // Identity for untrusted (non-attested) communication

    info!("Inside liddb main!");
    let untrusted_cert =
        fs::read("/opt/blindai/tls/host_server.pem").context("Reading host_server.pem")?;
    let untrusted_key =
        fs::read("/opt/blindai/tls/host_server.key").context("Reading host_server.key")?;
    let untrusted_identity = Identity::from_pem(&untrusted_cert, &untrusted_key);

    //Only performs dcap, so probably unnecessary without an enclave

    info!("Inside lib maindd!");
    tokio::spawn({
        let network_config = network_config.clone();
        async move {
            info!(
                "Starting server for User --> Enclave (unattested) untrusted communication at {}",
                network_config.client_to_enclave_untrusted_url
            );
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(untrusted_identity))?
                .add_service(untrusted::AttestationServer::new(MyAttestation {
                    quote_provider: dcap_quote_provider,
                }))
                .serve(network_config.client_to_enclave_untrusted_socket()?)
                .await?;
            Ok::<(), Box<dyn std::error::Error + Sync + Send>>(())
        }
    });

    info!("Inside lib maindd!");
    let exchanger = Exchanger::new(
        ModelStore::new().into(),
        my_identity.clone(),
        network_config.max_model_size,
        network_config.max_input_size,
    );

    info!("Inside lib main!");
    let server_future = Server::builder()
        .tls_config(ServerTlsConfig::new().identity((&enclave_identity).into()))?
        .max_frame_size(Some(65536))
        .add_service(ExchangeServer::new(exchanger))
        .serve(network_config.client_to_enclave_attested_socket()?);

    info!(
        "Starting server for User --> Enclave (attested TLS) trusted communication at {}",
        network_config.client_to_enclave_attested_url
    );
    println!("Server started, waiting for commands");

    if cfg!(SGX_MODE = "SW") {
        info!("Server running in simulation mode, attestation not available.");
    }

    // if std::env::var("BLINDAI_DISABLE_TELEMETRY").is_err() {
    //     telemetry::setup(telemetry_platform, telemetry_uid)?;
    //     info!("Telemetry is enabled.")
    // } else {
    //         info!("Telemetry is disabled.")
    //     }
    // telemetry::add_event(TelemetryEventProps::Started {}, None);

    server_future.await?;

    Ok(())
}
