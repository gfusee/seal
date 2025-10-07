// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use mysten_service::serve;
use sui_sdk::SuiClient;
use tracing::error;
use key_server::app;

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = mysten_service::logging::init();
    let (monitor_handle, app) = app::<SuiClient>().await?;

    tokio::select! {
        server_result = serve(app) => {
            error!("Server stopped with status {:?}", server_result);
            std::process::exit(1);
        }
        monitor_result = monitor_handle => {
            error!("Background tasks stopped with error: {:?}", monitor_result);
            std::process::exit(1);
        }
    }
}