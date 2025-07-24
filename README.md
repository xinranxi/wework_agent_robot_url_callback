# 企业微信 API 回调服务

这是一个基于 Python 的企业微信 API 回调服务，可以接收企业微信的消息并转发到 n8n(其他平台未测试) 的 webhook。

## 功能特点

- 支持配置多个企业微信应用（AgentId）
- 根据不同的 AgentId 转发到不同的 n8n(其他平台未测试) webhook
- 支持通过配置文件或环境变量进行配置
- 实现企业微信回调消息的验证和解密

## 安装

1. 克隆仓库
   ```
   git clone https://github.com/varequan/wework_n8n_url_callback
   cd wework_n8n_url_callback
   ```

2. 安装依赖
   ```
   pip install -r requirements.txt
   ```

## 配置

### 通过配置文件配置

1. 复制示例配置文件
   ```
   cp config.yaml.example config.yaml
   ```

2. 编辑 `config.yaml` 文件，填写企业微信的相关配置：
   - `corp_id`: 企业微信的企业ID
   - 为每个应用配置以下信息：
     - `agent_id`: 应用ID
     - `token`: 用于回调验证的 Token
     - `encoding_aes_key`: 用于消息解密的 EncodingAESKey
     - `secret`: 应用的 Secret
     - `webhook_url`: 要转发到的 n8n webhook URL
   - 为每个机器人配置以下信息：
     - `robot_id`: 自定义机器人ID
     - `token`: 用于回调验证的 Token
     - `encoding_aes_key`: 用于消息解密的 EncodingAESKey
     - `webhook_url`: 要转发到的 n8n webhook URL

### 通过环境变量配置

可以通过以下环境变量进行配置：

- `WEWORK_CORP_ID`: 企业微信企业ID
- 对于每个应用，添加以下环境变量（将 `{id}` 替换为应用ID）：
  - `WEWORK_AGENT_{id}_TOKEN`: 应用的 Token
  - `WEWORK_AGENT_{id}_AES_KEY`: 应用的 EncodingAESKey
  - `WEWORK_AGENT_{id}_SECRET`: 应用的 Secret
  - `WEWORK_AGENT_{id}_WEBHOOK`: 应用对应的 n8n webhook URL
- 对于每个机器人，添加以下环境变量（将 `{id}` 替换为机器人ID）：
  - `WEWORK_ROBOT_{id}_TOKEN`: 机器人的 Token
  - `WEWORK_ROBOT_{id}_AES_KEY`: 机器人的 EncodingAESKey
  - `WEWORK_ROBOT_{id}_WEBHOOK`: 机器人对应的 n8n webhook URL

例如，对于 agent_id 为 1000001 的应用，环境变量应该是：
```
WEWORK_CORP_ID=your_corp_id
WEWORK_AGENT_1000001_TOKEN=token_for_agent_1
WEWORK_AGENT_1000001_AES_KEY=encoding_aes_key_for_agent_1
WEWORK_AGENT_1000001_SECRET=secret_for_agent_1
WEWORK_AGENT_1000001_WEBHOOK=https://n8n.example.com/webhook/wework-app1
```

## 运行

### 开发环境运行

```
python app.py
```

默认在 `5000` 端口启动服务。

### 生产环境部署

使用 gunicorn 启动：

```
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 企业微信配置

1. 在企业微信管理后台创建自建应用
2. 在应用的"接收消息"设置中，填写：
   - URL：`http://your-server.com/wework/callback/{agent_id}`（替换 {agent_id} 为实际的应用ID）
   - 智能机器人URL:`http://your-server.com/wework/robot_callback/{robot_id}`（替换 {robot_id} 为实际的自定义的机器人ID）
   - Token：与配置中的 Token 保持一致
   - EncodingAESKey：与配置中的 encoding_aes_key 保持一致
3. 勾选需要接收的消息类型

## 转发到 webhook

消息会以 JSON 格式转发到配置的 n8n(其他平台未测试)webhook，格式为：

```json
{
  "agent_id": "1000001",
  "message": {
    "ToUserName": "企业ID",
    "FromUserName": "发送者ID",
    "CreateTime": "消息创建时间",
    "MsgType": "消息类型",
    "Content": "消息内容",
    "MsgId": "消息ID",
    "AgentID": "应用ID"
  }
}
```

## 许可证

MIT
