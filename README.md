# StarkArk

A secure, Rust-based CLI wallet and library for Starknet.

## Features

- 🛡️ **Secure Keystore**: Encrypted local storage for private keys using AES-256-GCM and Argon2.
- ⚡ **Starknet Integration**: Native support for Starknet accounts (OpenZeppelin), transfers, and deployments.
- 🖥️ **Interactive & CLI Modes**: Use it as a command-line tool or via an interactive menu.
- 🌍 **Multi-language Support**: Supports English and Chinese (configurable via `.env`).
- 📦 **Library Support**: Can be used as a Rust crate in other projects.

## Installation

### From Source

Ensure you have Rust installed.

```bash
git clone https://github.com/your-username/stark-ark.git
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
    The command above will tell you where the file was created (e.g., `~/.config/stark-ark/.env` on Linux). Open it and set your `STARKNET_RPC_URL`.

    ```dotenv
    STARKNET_RPC_URL=https://starknet-sepolia.public.blastapi.io
    ```

3.  **Check Configuration**:
    Verify your settings:

    ```bash
    stark-ark config show
    ```

## Usage

StarkArk can be used in **Interactive Mode** (by running without arguments) or **CLI Mode**.

### Interactive Mode

Simply run:

```bash
stark-ark
```

Follow the on-screen prompts to create a wallet, manage accounts, and send transactions.

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
Import an existing private key or a JSON account config (which allows custom salts/class hashes).

```bash
# Interactive import (recommended)
stark-ark import

# Or via command line (unsafe for history)
stark-ark import --key <PRIVATE_KEY_HEX_OR_JSON>
```

#### 4. Check Balance
Check the STRK balance of a specific account (by index).

```bash
stark-ark balance --index 0
```

#### 5. Deploy/Activate Account
Deploy the account contract to the Starknet network. This is required before you can execute transactions (other than `deploy`). You need to fund the address with ETH/STRK first.

```bash
stark-ark deploy --index 0
```

#### 6. Transfer Funds
Send STRK to another address.

```bash
stark-ark transfer --from-index 0 --to 0x123... --amount 1.5
```

#### 7. Export Private Key
Export the private key or full account configuration (JSON) for backup.

```bash
stark-ark export --index 0
```

#### 8. View Validators
View a link to active validators or check your configured default staker.

```bash
stark-ark validators
```

#### 9. Stake Funds
Delegate STRK tokens to a validator to earn rewards.

```bash
# Interactive mode (prompts for amount and validator)
stark-ark stake --index 0

# Non-interactive mode
stark-ark stake --index 0 --amount 10 --validator 0x123...
```

#### 10. Check Balance (Wallet + Staked)
View both your wallet balance and your delegated (staked) amount.

```bash
stark-ark balance --index 0
```

#### 11. Backup & Restore (Google Drive)
☁️  Securely backup your encrypted keystore to Google Drive.

**Prerequisites**:
You must configure your Google Cloud credentials in `.env` (see Configuration below).

```bash
# Upload keystore to Google Drive
stark-ark backup

# Restore keystore from Google Drive
stark-ark restore
```

## Google Drive Configuration

To use the backup feature, you need to provide your own Google Cloud "OAuth 2.0 Client ID" credentials.

1.  Go to **[Google Cloud Console](https://console.cloud.google.com/)**.
2.  Create a Project (e.g., "StarkArk Backup").
3.  Enable **Google Drive API** (API & Services > Library).
4.  Go to **API & Services > Credentials**.
5.  Click **Create Credentials** > **OAuth client ID**.
6.  Application Type: **Desktop app**.
7.  Copy the **Client ID** and **Client Secret**.
8.  **Important**: Go to **OAuth consent screen** > **Test users** and click **Add Users**. Add your own email address (e.g., `zhaojimmy13@gmail.com`). This is required because the app is in "Testing" mode.
9.  Add the credentials to your `.env` file:

```dotenv
GOOGLE_CLIENT_ID=your_client_id_here
GOOGLE_CLIENT_SECRET=your_client_secret_here
```

## License

MIT