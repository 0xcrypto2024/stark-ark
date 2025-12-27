# Stark Ark

`stark-ark` 是一个基于 Rust 开发的 Starknet 工具应用，集成了加密安全与命令行交互功能。

## 功能特性

- **Starknet 集成**: 使用 `starknet` crate 与 Starknet 网络进行交互。
- **安全加密**: 采用 `aes-gcm` (AES-GCM) 和 `argon2` (Argon2) 算法处理敏感数据加密与密码哈希。
- **命令行接口**: 通过 `clap` 提供直观的命令行参数解析与操作界面。
- **异步架构**: 基于 `tokio` 实现高性能的异步 I/O 操作。
- **配置管理**: 支持 `dotenv`，方便从 `.env` 文件加载环境变量配置。
- **数据处理**: 使用 `serde` 和 `serde_json` 进行高效的数据序列化与反序列化。

## 依赖概览

本项目使用了以下核心库：

- `starknet`: 区块链交互核心库
- `clap`: CLI 构建工具
- `tokio`: 异步运行时
- `aes-gcm` / `argon2` / `hex`: 安全、加密与编码
- `anyhow`: 错误处理
- `uuid`: 唯一标识符生成

## 快速开始

### 前置要求

- Rust (Edition 2021)

### 安装与构建

```bash
# 编译项目
cargo build --release
```

### 运行

由于项目使用了 `clap`，你可以通过以下命令查看可用的命令行参数：

```bash
# 查看帮助信息
cargo run -- --help
```

## 配置

请确保在项目根目录下配置 `.env` 文件以设置必要的环境变量（如 RPC URL 或私钥等）。