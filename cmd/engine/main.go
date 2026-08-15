// CryptoKit 密码引擎进程入口。
//
// 以 JSON Lines（每行一条 JSON-RPC 请求/响应）在 stdin/stdout 上与
// C# WinUI3 前端通信。此进程由前端拉起、随前端退出而终止，自身不落盘、
// 不创建任何临时目录或缓存，保证零 C 盘残留。
package main

import (
	"os"

	"cryptokit/engine"
)

func main() {
	e := engine.NewEngine()
	if err := e.Serve(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
