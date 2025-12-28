#!/bin/bash
set -e

# 确保脚本在项目根目录运行
cd "$(dirname "$0")"

CARGO_TOML="Cargo.toml"

if [ ! -f "$CARGO_TOML" ]; then
    echo "❌ 错误: 找不到 $CARGO_TOML"
    exit 1
fi

# 读取当前版本号 (匹配行首的 version = "x.y.z")
CURRENT_VERSION=$(grep -m 1 '^version = ' "$CARGO_TOML" | cut -d '"' -f 2)

if [ -z "$CURRENT_VERSION" ]; then
    echo "❌ 错误: 无法检测到当前版本号"
    exit 1
fi

echo "ℹ️  当前版本: $CURRENT_VERSION"

# 拆分版本号 X.Y.Z
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# 递增 Patch 版本号
NEW_PATCH=$((PATCH + 1))
NEW_VERSION="$MAJOR.$MINOR.$NEW_PATCH"

# 更新 Cargo.toml (使用临时文件以兼容 Linux 和 macOS 的 sed 差异)
sed "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$CARGO_TOML" > "${CARGO_TOML}.tmp" && mv "${CARGO_TOML}.tmp" "$CARGO_TOML"

echo "✅ 版本已升级: $CURRENT_VERSION -> $NEW_VERSION"
echo "🚀 现在你可以运行: git add Cargo.toml && git commit -m \"Bump version to $NEW_VERSION\" && git tag v$NEW_VERSION"