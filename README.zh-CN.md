# Microsoft Teams Channel SDK

`github.com/TrueWatchTech/truewatch-beak-agent-channel-teams` 将 Microsoft Teams 机器人账号接入 Beak Channel Gateway，实现通用
`sdk.Connector` 接口以及 teams 专属的入站入口。

平台专属逻辑（`Validate`、`SendText`、webhook 验签、入站事件解析）均已完整实现。
使用 `NewConnector()` 获取可直接注册的 `sdk.Connector`。

## Module

```
github.com/TrueWatchTech/truewatch-beak-agent-channel-teams
```

## 使用示例

```go
import (
    "fmt"

    beak "github.com/TrueWatchTech/truewatch-beak-agent-channel-teams"
)

func main() {
    connector := beak.NewConnector()
    fmt.Println(connector.Metadata().Label)
}
```

## 凭证字段

以下字段会出现在 Beak 控制台表单（`CredentialSchema`）中：

| Key | 名称 | Secret | 必填 |
| --- | --- | --- | --- |
| `client_id` | Microsoft App ID (Client ID) | 否 | 是 |
| `client_secret` | Client Secret (App Password) | 是 | 是 |
| `tenant_id` | Tenant ID (optional) | 否 | 否 |

后端字段（base URL、回调地址、offset、token 缓存）不会出现在表单中。

## 入站投递

模式：**webhook**

由 Beak host 持有 HTTP endpoint，并将原始请求转交给 `HandleWebhookRequest`，
由其完成验签与事件解析。

## Webhook 验签

策略：**jwt**

入站请求必须使用 `Authorization: Bearer <JWT>`。SDK 会校验 RS256 签名、
issuer、audience、exp/nbf、`serviceurl`，以及 Activity `channelId` 对应的
签名密钥 endorsement。Bot Framework OpenID/JWKS 会按 HTTP client 缓存 24 小时。

机器人在 Teams Activity 中的实际 mention 身份来自 `activity.recipient.id`
（通常是 `28:<MicrosoftAppId>`）；Beak 的稳定账号键仍使用 `client_id`。

## 出站

`Send` 将通用 `OutboundMessage`（`Text`、`Format`、`Mentions`、`MentionAll`）
映射到 Microsoft Teams 发送接口，并支持通用 `ThreadID`。`ThreadID` 会映射为
Bot Framework 被回复的 activity ID。用户 mention 同时生成可见的
`<at>...</at>` 文本和 Bot Framework mention entity。`MentionAll` 必须带明确的
Teams mention identity，SDK 不会猜测平台 ID。

入站 `replyToId` 会统一暴露为 `ThreadID` 和 `ReferencedMessage.MessageID`。
Bot Connector API 不能读取任意历史 Activity，因此引用正文为空时会通过
`Raw.fetch_error` 明确说明边界。Activity 顶层没有 `text` 时，SDK 会把
Adaptive Card 中的文字字段归一为通用入站正文。

Bot Framework 当前没有可通用映射的确认/表情接口，因此 `Acknowledge` 会返回
`status=unsupported`，Beak 无需按 Teams 写特殊分支。

## State

账号维度状态位于 `state/state.go`，通用集合与平台字段通过 `sdk.AccountStore` 持久化。
成功处理 webhook Activity 时会更新统一的 `stream_connection_state`、
`stream_last_activity_at` 和 `stream_last_event_at` 健康字段。

## 验证

```bash
go test ./...
cd conformance && go test ./...
```
