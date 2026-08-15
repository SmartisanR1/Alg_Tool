package utils

import "strings"

// TranslateConnError 将 Go 底层网络/TLS 错误翻译为中文原因描述。
// 无法识别的错误原样返回，保证用户至少能看到原始信息。
func TranslateConnError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	// TLS/证书相关（具体子串优先匹配）
	switch {
	case strings.Contains(msg, "unknown authority"):
		return "证书不受信任（自签名或未配置对应 CA 证书）"
	case strings.Contains(msg, "certificate has expired"):
		return "证书已过期，请更换证书"
	case strings.Contains(msg, "certificate is valid for"):
		return "证书域名不匹配（证书与目标主机不符）"
	case strings.Contains(msg, "server gave HTTP response to HTTPS client"):
		return "目标不是 TLS/TLCP 加密服务（返回了普通 HTTP 数据）"
	case strings.Contains(msg, "handshake failure"):
		return "TLS/TLCP 握手失败（协议版本或密码套件不匹配）"
	case strings.Contains(msg, "certificate"):
		return "证书校验失败（证书不受信任、已过期或与主机不匹配）"
	}

	// 网络连接相关
	switch {
	case strings.Contains(msg, "use of closed network connection"):
		return "连接已关闭，无法继续收发数据"
	case strings.Contains(msg, "connection refused"):
		return "连接被拒绝（目标端口未监听，或服务未启动）"
	case strings.Contains(msg, "connection reset by peer"):
		return "连接被对端重置（对方异常断开连接）"
	case strings.Contains(msg, "connection timed out"):
		return "连接超时（目标主机无响应，请检查网络或防火墙）"
	case strings.Contains(msg, "i/o timeout"):
		return "读写超时（对端响应过慢，可适当加大超时时间）"
	case strings.Contains(msg, "no such host"):
		return "主机不存在（域名解析失败，请检查主机地址）"
	case strings.Contains(msg, "network is unreachable"):
		return "网络不可达（请检查网络连接或路由设置）"
	case strings.Contains(msg, "host is unreachable"):
		return "主机不可达（请检查目标地址或路由设置）"
	case strings.Contains(msg, "broken pipe"):
		return "连接已断开（对端关闭了连接）"
	case strings.Contains(msg, "address already in use"):
		return "本地端口被占用，请更换端口"
	case strings.Contains(msg, "permission denied"):
		return "权限不足，无法建立连接"
	case strings.Contains(msg, "connection closed"):
		return "连接已被关闭"
	case strings.Contains(msg, "EOF"):
		return "对端提前关闭连接，未收到响应数据"
	default:
		return msg
	}
}
