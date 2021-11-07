use std::str::FromStr;

use web3::contract::{Contract, Options};
use web3::types::Address;

#[tokio::main]
async fn main() -> web3::contract::Result<()> {
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);

    let accounts = web3.eth().accounts().await?;

    let contract_addr = Address::from_str("0x5FbDB2315678afecb367f032d93F642f64180aa3").unwrap();
    let contract = Contract::from_json(
        web3.eth(),
        contract_addr,
        include_bytes!("../contract-abi/storage.json"),
    )
    .unwrap();

    let tx = contract
        .call(
            "addValue",
            ("test".to_string(),),
            accounts[0],
            Options::default(),
        )
        .await?;
    println!("TxHash: {}", tx);

    let result = contract.query("getValues", (), None, Options::default(), None);
    let storage: Vec<String> = result.await?;
    println!("Get values: {:?}", storage);

    Ok(())
}
