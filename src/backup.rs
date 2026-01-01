use anyhow::Result;
use google_drive3::DriveHub;
use yup_oauth2::{InstalledFlowAuthenticator, InstalledFlowReturnMethod};
use hyper::Client;
use hyper_rustls::{HttpsConnectorBuilder, HttpsConnector};
use hyper::client::HttpConnector;
use std::path::Path;
use google_drive3::api::File;

pub struct GoogleDriveBackend {
    hub: DriveHub<HttpsConnector<HttpConnector>>,
}

impl GoogleDriveBackend {
    pub async fn new(client_id: String, client_secret: String) -> Result<Self> {
        // 配置 OAuth2
        let secret = yup_oauth2::ApplicationSecret {
            client_id,
            client_secret,
            token_uri: "https://oauth2.googleapis.com/token".to_string(),
            auth_uri: "https://accounts.google.com/o/oauth2/auth".to_string(),
            redirect_uris: vec!["http://localhost".to_string(), "urn:ietf:wg:oauth:2.0:oob".to_string()],
            ..Default::default()
        };

        let auth = InstalledFlowAuthenticator::builder(
            secret,
            InstalledFlowReturnMethod::HTTPRedirect,
        )
        .persist_tokens_to_disk("token_cache.json")
        .build()
        .await?;
        
        // 强制预先请求正确的 Scope，确保 Token 包含权限
        auth.token(&["https://www.googleapis.com/auth/drive"]).await?;

        let connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http()
            .enable_http1()
            .build();

        let hub = DriveHub::new(Client::builder().build(connector), auth);
        Ok(Self { hub })
    }

    /// 上传文件到 Google Drive (根目录)
    pub async fn upload_file(&self, filepath: &Path) -> Result<String> {
        let filename = filepath.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

        // 读取文件内容
        let mut file = std::fs::File::open(filepath)?;

        let req = File {
            name: Some(filename.to_string()),
            ..Default::default()
        };

        let result = self.hub
            .files()
            .create(req)
            .upload_resumable(&mut file, "application/json".parse().unwrap())
            .await;

        match result {
            Ok((_, file)) => {
                let id = file.id.unwrap_or_default();
                Ok(id)
            },
            Err(e) => Err(anyhow::anyhow!("Upload failed: {}", e)),
        }
    }

    /// 列出所有备份文件
    pub async fn list_backups(&self) -> Result<Vec<(String, String, String)>> {
        let result = self.hub.files().list()
            .q("trashed = false and name contains 'keystore'")
            .param("fields", "files(id, name, createdTime)")
            .add_scope("https://www.googleapis.com/auth/drive")
            .doit()
            .await?;

        let mut backups = Vec::new();
        if let Some(files) = result.1.files {
            for f in files {
                backups.push((
                    f.id.unwrap_or_default(),
                    f.name.unwrap_or_default(),
                    f.created_time.map(|t: chrono::DateTime<chrono::Utc>| t.to_string()).unwrap_or_default(),
                ));
            }
        }
        Ok(backups)
    }

    /// 下载文件
    pub async fn download_file(&self, file_id: &str, target_path: &Path) -> Result<()> {
        let (response, _): (hyper::Response<hyper::Body>, google_drive3::api::File) = self.hub.files().get(file_id)
            .acknowledge_abuse(true)
            .param("alt", "media")
            .add_scope("https://www.googleapis.com/auth/drive")
            .doit()
            .await?;
        
        if !response.status().is_success() {
             return Err(anyhow::anyhow!("Download request failed: {}", response.status()));
        }

        let body = hyper::body::to_bytes(response.into_body()).await?;
        std::fs::write(target_path, body)?;
        
        Ok(())
    }
}
