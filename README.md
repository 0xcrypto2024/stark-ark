# StarkArk

A secure, Rust-based CLI wallet and library for Starknet.

## Features

- 🤖 **AI-First Design**: Native JSON output (`--json`), secure non-interactive mode, and **MCP Server** support for autonomous agents.
- 💱 **DEX Integration**: Built-in **AVNU** swap aggregator support for best-price execution and token discovery.
- 🦁 **Degen UX**: High-speed TUI with arrow-key menus, ASCII banners, and live spinners for humans.
- 🛡️ **Secure Keystore**: Encrypted local storage for private keys using AES-256-GCM and Argon2.
- ⚡ **Starknet Integration**: Native support for Starknet accounts (OpenZeppelin), transfers, and deployments.
- 📦 **Library Support**: Can be used as a Rust crate in other projects.

## Installation

### From Source

Ensure you have Rust installed.

```bash
git clone https://github.com/0xcrypto2024/stark-ark.git
cd stark-ark
cargo install --path .
```

## Configuration

Before using StarkArk, you need to configure the RPC endpoint and other settings.

1.  **Initialize Configuration**:
    Run the following command to generate a default configuration file in your system's config directory:

    ```bash
    stark-ark config init
    ```

2.  **Edit Configuration**:
    The command above will tell you where the file was created. Open it and set your `STARKNET_RPC_URL` and optionally `STARK_ARK_PASSWORD` for autonomous mode.

    ```dotenv
    STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io
    
    # Optional: For autonomous AI Agent / MCP usage without prompts
    STARK_ARK_PASSWORD=my_secure_wallet_password
    ```

3.  **Check Configuration**:
    Verify your settings:

    ```bash
    stark-ark config show
    ```


## 🤖 AI & Automation Guide

StarkArk is built to be the best Starknet wallet for AI Agents.

### 1. **Model Context Protocol (MCP) Server**
StarkArk transforms into an MCP server, allowing AI agents (like Claude Desktop) to directly "see" and "use" your wallet safely.

**Prerequisites**:
- Set `STARK_ARK_PASSWORD` in your environment or `.env` file.

**Run Server**:
```bash
stark-ark mcp
```

**Exposed Tools**:
- `list_accounts()`: View all available wallet accounts.
- `get_balance(token_symbol, account_address?)`: Check holdings. If address is omitted, scans **all accounts** for ETH, STRK, and **Staked STRK**.
- `stake(amount, validator_address, account_address?)`: Delegate STRK to a validator.
- `unstake(amount, pool_address, account_address?)`: Signal intent to unstake.
- `withdraw_unstaked(pool_address, account_address?)`: Withdraw unbonded funds.
- `swap(sell, buy, amount, account_address?)`: Execute swaps via AVNU.
- `transfer(to, amount, account_address?)`: Send STRK.

### Example Prompts for Claude
Once connected, you can simply ask Claude in natural language:

- **Check Balance**: "What are my balances?" (Scans all accounts) or "Check ETH on my main account."
- **Manage Accounts**: "List all my wallet accounts."
- **Staking**:
  - "Stake 100 STRK to 0x123..."
  - "Unstake 50 STRK from 0x123..."
  - "Withdraw my unstaked funds."
- **Swap**: "Swap 10 STRK for ETH using my second account."
- **Transfer**: "Send 5 STRK to 0x123..."

Claude will verify the tool call with you before executing any transaction.

### 💡 Use Case: Automated Portfolio Management

Imagine asking Claude to manage your portfolio purely through natural language.

**User**: "Check my balances. If I have more than 100 STRK, swap half of it to ETH and stake the rest to the default validator."

**Claude (Agent)**:
1.  **Calls `get_balance()`**: "You have 500 STRK and 0.1 ETH on your main account."
2.  **Reasoning**: "500 > 100. I need to swap 250 STRK to ETH and stake 250 STRK."
3.  **Calls `swap(sell="STRK", buy="ETH", amount=250)`**: *Executes swap via AVNU.*
4.  **Calls `stake(amount=250, validator="0x...")`**: *Delegates remaining funds.*

**Result**: Your portfolio is rebalanced and staking rewards are active, all from one sentence.

### Configuration for Claude Desktop

To use StarkArk with **Claude Desktop**, edit your `claude_desktop_config.json` file:

- **MacOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the following entry:

```json
{
  "mcpServers": {
    "stark-ark": {
      "command": "/absolute/path/to/stark-ark",
      "args": ["mcp"],
      "env": {
        "STARKNET_RPC_URL": "https://starknet-sepolia.public.blastapi.io",
        "STARK_ARK_PASSWORD": "your_wallet_password",
        "KEYSTORE_FILE": "/absolute/path/to/keystore.json",
        "STRK_CONTRACT_ADDRESS": "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
        "OZ_CLASS_HASH": "0x061dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f",
        "STAKING_CONTRACT_ADDRESS": "0x03745ab04a431fc02871a139be6b93d9260b0ff3e779ad9c8b377183b23109f1"
      }
    }
  }
}
```

> **Tip**: Run `which stark-ark` (or `pwd` in the target dir) to find the absolute path to the binary. Ensure `KEYSTORE_FILE` points to the correct location if it's not in the default directory.



### 2. Enable Machine Output (CLI Mode)
Use the `--json` flag to get strict, structured JSON output for parsing if you are building your own wrapper.

```bash
stark-ark --json balance --index 0
# Output: {"index":0,"address":"0x...","balance":100.0,"unit":"STRK"}
```

## Usage

StarkArk can be used in **Interactive Mode** (by running without arguments) or **CLI Mode**.

### Interactive Mode (Degen UX)

Run `stark-ark` without arguments to enter the TUI mode. 

- **Arrow Keys ⬆️ ⬇️**: Navigate menus.
- **Enter ↵**: Select options.
- **Real-time Spinners**: Watch network operations in style.
- **Dynamic Token Balances**: Automatically scans and displays your token holdings.

```bash
stark-ark
```

### CLI Commands

#### 1. Create a New Account
Generate a new private key and add it to your keystore.

```bash
stark-ark new
```

#### 2. List Accounts
View all accounts managed by the keystore.

```bash
stark-ark list
```

#### 3. Import an Account
Import an existing private key or a JSON account config.

```bash
# Interactive import (recommended)
stark-ark import
```

#### 4. Swap Tokens (AVNU) 🆕
Swap tokens directly from the CLI using the AVNU aggregator.

```bash
# Swap 10 STRK for ETH
stark-ark swap --sell STRK --buy ETH --amount 10 --index 0
```
Supports both tickers (STRK, ETH, USDC) and contract addresses.

#### 5. List Supported Tokens
View the list of tokens supported by AVNU.

```bash
stark-ark tokens
```

#### 6. Check Balance
Check the STRK balance of a specific account (by index).

```bash
stark-ark balance --index 0
```

#### 7. Deploy/Activate Account
Deploy the account contract to the Starknet network.

```bash
stark-ark deploy --index 0
```

#### 8. Transfer Funds
Send STRK to another address.

```bash
stark-ark transfer --from-index 0 --to 0x123... --amount 1.5
```

#### 9. Export Private Key
Export the private key or full account configuration (JSON) for backup.

```bash
stark-ark export --index 0
```

#### 10. Stake Funds
Delegate STRK tokens to a validator to earn rewards.

```bash
stark-ark stake --index 0 --amount 10 --validator 0x123...
```

#### 11. Backup & Restore (Google Drive)
☁️  Securely backup your encrypted keystore to Google Drive.

**Prerequisites**:
Enable Google Drive API and set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`.

```bash
# Upload keystore to Google Drive
stark-ark backup

# Restore keystore from Google Drive
stark-ark restore
```

## License

MIT