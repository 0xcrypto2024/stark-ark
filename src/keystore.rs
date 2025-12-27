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

impl Keystore {
    /// 🔐 加密 (支持保存私钥列表)
    pub fn encrypt(password: &str, private_keys: &[String]) -> Result<Self> {
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
        let payload = serde_json::to_string(private_keys)?;
        
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

    /// 🔓 解密 (返回私钥列表)
    pub fn decrypt(&self, password: &str) -> Result<Vec<String>> {
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

        // 🔄 兼容性处理：尝试解析为数组，如果失败则视为旧版的单个字符串
        match serde_json::from_str::<Vec<String>>(&decrypted_str) {
            Ok(keys) => Ok(keys),
            Err(_) => Ok(vec![decrypted_str]),
        }
    }

    /// ➕ 添加新账户
    pub fn add_new_account(original: &Self, password: &str) -> Result<Self> {
        let mut keys = original.decrypt(password)?;
        let new_key = Self::generate_new_key();
        keys.push(new_key);
        Self::encrypt(password, &keys)
    }

    pub fn generate_new_key() -> String {
        let signing_key = SigningKey::from_random();
        format!("{:#x}", signing_key.secret_scalar())
    }

    /// 🧬 计算地址 (依赖配置中的 Class Hash)
    pub fn derive_address(private_key_hex: &str, class_hash_hex: &str) -> Result<String> {
        let priv_key_felt = Felt::from_hex(private_key_hex)?;
        let signer = SigningKey::from_secret_scalar(priv_key_felt);
        let public_key = signer.verifying_key().scalar();
        
        let class_hash = Felt::from_hex(class_hash_hex)?;
        let salt = public_key;
        let deployer = Felt::ZERO;
        let constructor_calldata = vec![public_key];

        let address = get_contract_address(
            salt,
            class_hash,
            &constructor_calldata,
            deployer,
        );

        Ok(format!("{:#x}", address))
    }
}