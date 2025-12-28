use serde::{Deserialize, Serialize};
use anyhow::Result;
use aes_gcm::{Aes256Gcm, Key, KeyInit, aead::Aead, Nonce};
use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, rand_core::OsRng}};
use starknet::core::types::Felt;
use starknet::core::utils::get_contract_address;
use starknet::signers::SigningKey;
use rand::RngCore;

#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    pub version: u32,
    pub id: String,
    pub ciphertext: String,
    pub nonce: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountConfig {
    pub private_key: String,
    pub salt: Option<String>,       // Hex string. If None, defaults to Public Key (Standard OZ)
    pub class_hash: Option<String>, // Hex string. If None, defaults to Config's OZ hash
    pub alias: Option<String>,
    pub address: Option<String>,    // Hex string. Cached address.
}

impl Keystore {
    /// 🔐 加密 (保存账户配置列表)
    pub fn encrypt(password: &str, accounts: &[AccountConfig]) -> Result<Self> {
        let mut rng = OsRng;
        let salt = SaltString::generate(&mut rng);
        let argon2 = Argon2::default();
        let salt_string = salt.to_string();
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Hash error: {}", e))?;
        
        let output = password_hash.hash.ok_or_else(|| anyhow::anyhow!("Hash output error"))?;
        let key = Key::<Aes256Gcm>::from_slice(&output.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // 将列表转为 JSON 字符串后加密
        let payload = serde_json::to_string(accounts)?;
        
        let ciphertext = cipher
            .encrypt(nonce, payload.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;

        Ok(Self {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            ciphertext: hex::encode(ciphertext),
            nonce: hex::encode(nonce_bytes),
            salt: salt_string,
        })
    }

    /// 🔓 解密 (返回账户配置列表，自动处理旧版格式)
    pub fn decrypt(&self, password: &str) -> Result<Vec<AccountConfig>> {
        let salt = SaltString::from_b64(&self.salt)
            .map_err(|_| anyhow::anyhow!("Invalid salt"))?;
        
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Hash error: {}", e))?;

        let output = password_hash.hash.ok_or_else(|| anyhow::anyhow!("Hash output error"))?;
        let key = Key::<Aes256Gcm>::from_slice(&output.as_bytes()[..32]);
        let cipher = Aes256Gcm::new(key);

        let nonce_bytes = hex::decode(&self.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext_bytes = hex::decode(&self.ciphertext)?;

        let decrypted_bytes = cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|_| anyhow::anyhow!("❌ 密码错误或文件损坏"))?;

        let decrypted_str = String::from_utf8(decrypted_bytes)?;

        // 🔄 兼容性处理：
        // 1. 尝试解析为新版 Vec<AccountConfig>
        if let Ok(configs) = serde_json::from_str::<Vec<AccountConfig>>(&decrypted_str) {
            return Ok(configs);
        }

        // 2. 失败则尝试解析为旧版 Vec<String> 并迁移
        let keys: Vec<String> = serde_json::from_str(&decrypted_str)
            .or_else(|_| serde_json::from_str::<String>(&decrypted_str).map(|s| vec![s])) // 兼容单字符串
            .map_err(|_| anyhow::anyhow!("Invalid keystore format"))?;

        Ok(keys.into_iter().map(|k| AccountConfig {
            private_key: k,
            salt: None,      // 旧版默认使用公钥作为 Salt
            class_hash: None, // 旧版未存储 Class Hash，将在运行时使用 Config 默认值
            alias: None,
            address: None,
        }).collect())
    }

    /// ➕ 添加新账户
    pub fn add_account(original: &Self, password: &str, account: AccountConfig) -> Result<Self> {
        let mut accounts = original.decrypt(password)?;
        // 允许相同私钥，只要 Salt 或 Class Hash 不同 (支持单私钥多账户)
        if accounts.iter().any(|a| 
            a.private_key == account.private_key && 
            a.salt == account.salt && 
            a.class_hash == account.class_hash
        ) {
             return Err(anyhow::anyhow!("Account already exists"));
        }
        accounts.push(account);
        Self::encrypt(password, &accounts)
    }

    pub fn generate_new_key() -> String {
        let signing_key = SigningKey::from_random();
        format!("{:#x}", signing_key.secret_scalar())
    }

    /// 🧬 计算地址 (智能判断使用存储的配置还是默认值)
    pub fn compute_address(account: &AccountConfig, default_class_hash: &str) -> Result<String> {
        // 1. 如果有缓存地址，直接返回 (可选，这里为了准确性每次都算一下，或者你可以信任缓存)
        // if let Some(addr) = &account.address { return Ok(addr.clone()); }

        let priv_key_felt = Felt::from_hex(&account.private_key)?;
        let signer = SigningKey::from_secret_scalar(priv_key_felt);
        let public_key = signer.verifying_key().scalar();
        
        // 2. 确定 Class Hash
        let class_hash_hex = account.class_hash.as_deref().unwrap_or(default_class_hash);
        let class_hash = Felt::from_hex(class_hash_hex)?;

        // 3. 确定 Salt (如果有自定义 Salt 则使用，否则使用公钥)
        let salt = match &account.salt {
            Some(s) => Felt::from_hex(s)?,
            None => public_key,
        };
        
        let deployer = Felt::ZERO;
        let constructor_calldata = vec![public_key];

        let address = get_contract_address(
            salt,
            class_hash,
            &constructor_calldata,
            deployer,
        );

        let bytes = address.to_bytes_be();
        Ok(format!("0x{}", hex::encode(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_flow() {
        let password = "strong_password";
        let account = AccountConfig {
            private_key: "0x12345".to_string(),
            salt: Some("0xabc".to_string()),
            class_hash: None,
            alias: Some("TestAccount".to_string()),
            address: None,
        };
        
        // 1. Encrypt
        let keystore = Keystore::encrypt(password, &[account.clone()]).expect("Encryption failed");
        
        // 2. Decrypt
        let decrypted_accounts = keystore.decrypt(password).expect("Decryption failed");
        
        assert_eq!(decrypted_accounts.len(), 1);
        let decrypted_acc = &decrypted_accounts[0];
        
        assert_eq!(decrypted_acc.private_key, account.private_key);
        assert_eq!(decrypted_acc.salt, account.salt);
        assert_eq!(decrypted_acc.alias, account.alias);
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let password = "correct_password";
        let account = AccountConfig {
            private_key: "0x1".to_string(),
            salt: None,
            class_hash: None,
            alias: None,
            address: None,
        };
        let keystore = Keystore::encrypt(password, &[account]).unwrap();

        let result = keystore.decrypt("wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_account_logic() {
        let password = "password";
        let acc1 = AccountConfig {
            private_key: "0x1".to_string(),
            salt: None,
            class_hash: None,
            alias: None,
            address: None,
        };
        let keystore = Keystore::encrypt(password, &[acc1.clone()]).unwrap();

        let acc2 = AccountConfig {
            private_key: "0x2".to_string(),
            salt: None,
            class_hash: None,
            alias: None,
            address: None,
        };

        let updated_keystore = Keystore::add_account(&keystore, password, acc2.clone()).unwrap();
        let accounts = updated_keystore.decrypt(password).unwrap();

        assert_eq!(accounts.len(), 2);
        assert!(accounts.iter().any(|a| a.private_key == "0x1"));
        assert!(accounts.iter().any(|a| a.private_key == "0x2"));
    }

    #[test]
    fn test_duplicate_prevention() {
        let password = "password";
        let acc1 = AccountConfig {
            private_key: "0x1".to_string(),
            salt: Some("0xsalt".to_string()),
            class_hash: Some("0xclass".to_string()),
            alias: None,
            address: None,
        };
        let keystore = Keystore::encrypt(password, &[acc1.clone()]).unwrap();

        // 1. Exact duplicate -> Error
        let err = Keystore::add_account(&keystore, password, acc1.clone());
        assert!(err.is_err());

        // 2. Same private key, different salt -> OK
        let acc2 = AccountConfig {
            private_key: "0x1".to_string(),
            salt: Some("0xDIFFERENT".to_string()),
            class_hash: Some("0xclass".to_string()),
            alias: None,
            address: None,
        };
        let ok = Keystore::add_account(&keystore, password, acc2);
        assert!(ok.is_ok());
    }

    #[test]
    fn test_generate_new_key() {
        let key = Keystore::generate_new_key();
        assert!(key.starts_with("0x"));
        assert!(key.len() > 2);
    }
}