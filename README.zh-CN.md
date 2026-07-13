# Microsoft Teams Channel SDK

`github.com/TrueWatch/beak-agent-channel-teams` 将 Microsoft Teams 机器人账号接入 Beak Channel Gateway，实现通用
`sdk.Connector` 接口以及 teams 专属的入站入口。

平台专属逻辑（`Validate`、`SendText`、webhook 验签、入站事件解析）均已完整实现。
使用 `NewConnector()` 获取可直接注册的 `sdk.Connector`。

## Module

```
github.com/TrueWatch/beak-agent-channel-teams
```

## 使用示例

```go
import (
    "fmt"

    beak "github.com/TrueWatch/beak-agent-channel-teams"
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



## 出站

`Send` 将通用 `OutboundMessage`（`Text`、`Format`、`Mentions`、`MentionAll`）
映射到 Microsoft Teams 发送接口（`/v3/conversations/{conversationId}/activities`）。

## State

账号维度状态位于 `state/state.go`，通用集合与平台字段通过 `sdk.AccountStore` 持久化。
