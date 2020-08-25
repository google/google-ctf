// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use log::{debug, warn};
use pwn_tracing::bst::BinarySearchTree;
use uuid::Uuid;

const BIND_ADDR: &str = "0.0.0.0:1337";
const DEFAULT_READ_LIMIT: usize = 0x1000000;

async fn accept(mut stream: TcpStream, checks: Vec<Uuid>) -> std::io::Result<()> {
    let read_limit = std::env::var("GCTF_READ_LIMIT")
        .map(|s| s.parse().unwrap())
        .unwrap_or(DEFAULT_READ_LIMIT);

    debug!("Accepted connection");
    let bytes = (&stream).bytes().take(read_limit).map(|b| b.unwrap());
    let chunks = {
        // Ugh, async_std::prelude::StreamExt doesn't have chunks(),
        // but it conflicts with futures::stream::StreamExt for the methods it
        // does have.
        use futures::stream::StreamExt;
        bytes.chunks(16)
    };
    let mut count: u32 = 0;
    let ids = chunks.filter_map(|bytes| {
        count += 1;
        Uuid::from_slice(&bytes).ok()
    });
    let tree = {
        use futures::stream::StreamExt;
        ids.collect::<BinarySearchTree<_>>()
    }
    .await;
    debug!("Received {} IDs", count);
    stream.write_all(&count.to_be_bytes()).await?;

    debug!("Checking uploaded IDs for any matches");
    checks
        .iter()
        .filter(|check| tree.contains(check))
        .for_each(|check| warn!("Uploaded IDs contain {}!", check));
    stream.shutdown(std::net::Shutdown::Both)?;
    debug!("Done");
    Ok(())
}

#[async_std::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let checks: Vec<Uuid> = std::env::args()
        .skip(1)
        .map(|arg| Uuid::from_slice(arg.as_bytes()).unwrap())
        .collect();

    debug!("Loaded checks: {:?}", checks);

    let listener = TcpListener::bind(BIND_ADDR).await?;
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        let stream = stream?;
        async_std::task::spawn(accept(stream, checks.clone()));
    }
    Ok(())
}
