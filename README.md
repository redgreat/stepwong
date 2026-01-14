# stepwong

ZEPP Life API 刷微信支付宝步数

## ✨ 新功能

### Token 缓存机制（2026-01-14）
- ✅ 支持 Token 缓存，减少登录频率
- ✅ AES-128 加密存储，保护账号安全
- ✅ 自动复用有效 Token，降低风控风险
- ✅ 详细错误日志，便于问题排查

## 📦 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 配置环境变量
在 GitHub Secrets 或本地环境中配置：

| 变量名 | 说明 | 必需 | 示例 |
|--------|------|------|------|
| `CONFIG` | 配置JSON | ✅ | 见下方说明 |
| `AES_KEY` | 16字节加密密钥 | ⭐ 推荐 | `1234567890abcdef` |

### 3. CONFIG 配置示例
```json
{
  "USER": "13800138000#user@example.com",
  "PWD": "password1#password2",
  "MIN_STEP": 18000,
  "MAX_STEP": 25000,
  "SLEEP_GAP": 5
}
```

## 🔐 Token 缓存配置

**强烈推荐**配置 `AES_KEY` 以启用 Token 缓存功能：

1. 生成 16 字节密钥（16 个字符）
2. 在 GitHub Secrets 中添加 `AES_KEY`
3. 首次运行后会自动生成 `encrypted_tokens.data` 文件
4. 后续运行将自动使用缓存的 Token

详细说明请查看：[Token 缓存功能文档](docs/TOKEN_CACHE.md)

## 📝 更新日志

### 2026-01-14
- ✨ 新增 Token 缓存机制
- 🐛 修复登录 JSON 解析错误
- 📝 添加详细错误日志
- 🔒 支持 AES 加密存储

## ⚠️ 注意事项

1. **AES_KEY 必须是 16 字节**（16 个字符）
2. 不要将 `encrypted_tokens.data` 提交到 Git
3. 保管好 AES_KEY，泄露后需立即更换
4. 未配置 AES_KEY 时，功能会自动降级为每次登录模式

## 📄 许可证

MIT License
