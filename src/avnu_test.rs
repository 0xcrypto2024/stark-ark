use serde::Deserialize;
use std::error::Error;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    // Basic test for AVNU Swap Quote
    println!("Testing AVNU Swap Quote...");
    let output = Command::new("curl")
        .arg("-s")
        .arg("https://starknet.api.avnu.fi/swap/v1/quotes?sellTokenAddress=0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7&buyTokenAddress=0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8&sellAmount=100000000000000000") // 1 ETH to USDC (approx)
        .output()?;
    
    if output.status.success() {
        println!("AVNU Swap Quote Response: {}", String::from_utf8_lossy(&output.stdout));
    } else {
        eprintln!("AVNU Swap Quote Failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Check for "Lending" or similar in /sources or similar if exists
    // Using a broad search on /sources if it was a valid endpoint, but just checking quotes is enough to verify connectivity.
    // I made up the /sources endpoint guess, common in aggregators.
    println!("\nTesting AVNU Sources...");
    let output_sources = Command::new("curl")
        .arg("-s")
        .arg("https://starknet.api.avnu.fi/swap/v1/sources")
        .output()?;
        
    if output_sources.status.success() {
        println!("AVNU Sources Response: {}", String::from_utf8_lossy(&output_sources.stdout));
    }

    Ok(())
}
