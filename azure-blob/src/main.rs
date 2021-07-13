use azure_core::prelude::Range;
use azure_storage::blob::prelude::{AsBlobClient, AsContainerClient};
use azure_storage::clients::AsStorageClient;
use azure_storage::core::clients::StorageAccountClient;
use std::error::Error;

#[tokio::main]
async fn main() {
    let result = get().await.unwrap();
    println!("current: {}", result);

    put("++++test").await.unwrap();

    let result = get().await.unwrap();
    println!("current: {}", result);
}

async fn get() -> Result<String, Box<dyn Error + Send + Sync>> {
    let account =
        std::env::var("STORAGE_ACCOUNT").expect("Set env variable STORAGE_ACCOUNT first!");
    let key =
        std::env::var("STORAGE_ACCOUNT_KEY").expect("Set env variable STORAGE_ACCOUNT_KEY first!");

    let http_client = azure_core::new_http_client();
    let storage_account_client =
        StorageAccountClient::new_access_key(http_client.clone(), account, key);

    let storage_client = storage_account_client.as_storage_client();

    let container_name = "keys";
    let blob_name = "test.txt";

    let blob_client = storage_client
        .as_container_client(container_name)
        .as_blob_client(blob_name);

    let response = blob_client
        .get()
        .range(Range::new(0, 128000))
        .execute()
        .await?;

    let s_content = String::from_utf8(response.data.to_vec())?;

    Ok(s_content)
}

async fn put(data: &'static str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let account =
        std::env::var("STORAGE_ACCOUNT").expect("Set env variable STORAGE_ACCOUNT first!");
    let key =
        std::env::var("STORAGE_ACCOUNT_KEY").expect("Set env variable STORAGE_ACCOUNT_KEY first!");

    let http_client = azure_core::new_http_client();
    let storage_account_client =
        StorageAccountClient::new_access_key(http_client.clone(), account, key);

    let storage_client = storage_account_client.as_storage_client();

    let container_name = "keys";
    let blob_name = "test.txt";

    let blob_client = storage_client
        .as_container_client(container_name)
        .as_blob_client(blob_name);

    let _res = blob_client
        .put_block_blob(data.as_bytes())
        .content_type("text/plain")
        .execute()
        .await?;

    Ok(())
}
