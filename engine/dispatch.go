package engine

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

// maxLineBytes 单条请求/响应的最大长度。国密/PQC 大密钥、报文性能测试
// 返回体可能很大，放宽到 64 MiB。
const maxLineBytes = 64 * 1024 * 1024

// Request 是 C# 前端发来的 JSON-RPC 风格请求。
// params 恒为 JSON 数组，元素与目标方法形参一一对应：
//
//	单参方法  -> [ { ... } ] 或 [ 123 ] / [ "str" ]
//	双参方法  -> [ a, b ]
//	无参方法  -> []
type Request struct {
	ID     interface{}       `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// Response 是引擎返回的 JSON-RPC 风格响应。
// Result 只有在成功时存在；Error 只在失败时存在（含协议错误与未知方法）。
type Response struct {
	ID     interface{}     `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *string         `json:"error,omitempty"`
}

func strPtr(s string) *string { return &s }

// Dispatch 按方法名反射调用 Engine 的对应方法。
// method 与 params 均来自不可信输入，故先做数量校验与逐参反序列化校验。
func (e *Engine) Dispatch(method string, params []json.RawMessage) (json.RawMessage, error) {
	m := reflect.ValueOf(e).MethodByName(method)
	if !m.IsValid() {
		return nil, fmt.Errorf("unknown method: %q", method)
	}
	mt := m.Type()
	if mt.NumIn() != len(params) {
		return nil, fmt.Errorf("method %q expects %d param(s), got %d", method, mt.NumIn(), len(params))
	}
	if mt.NumOut() != 1 {
		return nil, fmt.Errorf("method %q must return exactly 1 value", method)
	}

	args := make([]reflect.Value, mt.NumIn())
	for i := 0; i < mt.NumIn(); i++ {
		arg := reflect.New(mt.In(i))
		if err := json.Unmarshal(params[i], arg.Interface()); err != nil {
			return nil, fmt.Errorf("method %q param %d: %w", method, i+1, err)
		}
		args[i] = arg.Elem()
	}

	// 结果结构体内部用 Error 字段承载业务失败（Success=false），
	// 这里仅负责把返回值序列化回去，业务失败由前端读 Success 判断。
	out := m.Call(args)
	return json.Marshal(out[0].Interface())
}

// Serve 从 r 逐行读取 JSON 请求、把响应逐行写回 w，直到输入 EOF。
// 该函数不触碰 os.Stdout 之外的任何输出，保证 stdio 通道纯净。
func (e *Engine) Serve(r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1024*1024), maxLineBytes)

	enc := json.NewEncoder(w)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(Response{Error: strPtr("invalid request: " + err.Error())})
			continue
		}
		res, err := e.Dispatch(req.Method, req.Params)
		if err != nil {
			_ = enc.Encode(Response{ID: req.ID, Error: strPtr(err.Error())})
			continue
		}
		_ = enc.Encode(Response{ID: req.ID, Result: res})
	}
	return sc.Err()
}
