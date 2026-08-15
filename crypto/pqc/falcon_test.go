package pqc

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	falcon "github.com/lattice-safe/falcon-go"
)

// parseFalconVec 解析 falcon512_vec.txt 向量文件。
// 文件格式（每 4 行为一组）：
//   TEST n
//   msg=<hex>
//   pk=<hex>
//   sk=<hex>
//   sig=<hex>
//   verify=OK
type falconVec struct {
	msg []byte
	pk  []byte
	sk  []byte
	sig []byte
}

func parseFalconVec(t *testing.T, path string) []falconVec {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开向量文件失败: %v", err)
	}
	defer f.Close()

	var vecs []falconVec
	var cur falconVec
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "TEST"):
			cur = falconVec{}
		case strings.HasPrefix(line, "msg="):
			cur.msg, _ = hex.DecodeString(strings.TrimPrefix(line, "msg="))
		case strings.HasPrefix(line, "pk="):
			cur.pk, _ = hex.DecodeString(strings.TrimPrefix(line, "pk="))
		case strings.HasPrefix(line, "sk="):
			cur.sk, _ = hex.DecodeString(strings.TrimPrefix(line, "sk="))
		case strings.HasPrefix(line, "sig="):
			cur.sig, _ = hex.DecodeString(strings.TrimPrefix(line, "sig="))
		case strings.HasPrefix(line, "verify="):
			vecs = append(vecs, cur)
		}
	}
	if len(vecs) == 0 {
		t.Fatal("向量文件中没有解析到任何测试向量")
	}
	return vecs
}

// TestFalconKAT: 用官方 FALCON 参考实现生成的确定性向量做端到端比对。
// FALCON-512: 公钥 897B, 私钥 1281B, 签名 809B。
func TestFalconKAT(t *testing.T) {
	vecs := parseFalconVec(t, "testdata/falcon512_vec.txt")
	for i, v := range vecs {
		if len(v.pk) != 897 || len(v.sk) != 1281 || len(v.sig) != 809 {
			t.Fatalf("test %d: 尺寸异常 pk=%d sk=%d sig=%d", i, len(v.pk), len(v.sk), len(v.sig))
		}

		// 私钥派生公钥必须与向量中的公钥一致（校验私钥解析/编码正确）
		derived, err := falcon.PublicKeyFromPrivate(v.sk)
		if err != nil {
			t.Fatalf("test %d: 私钥解析失败: %v", i, err)
		}
		if hex.EncodeToString(derived) != hex.EncodeToString(v.pk) {
			t.Fatalf("test %d: 由私钥派生的公钥与向量公钥不一致", i)
		}

		// 官方签名必须通过我们的验签接口
		vr := FalconVerify(SLHDSAVerifyRequest{
			PublicKey: hex.EncodeToString(v.pk),
			Data:      hex.EncodeToString(v.msg),
			Signature: hex.EncodeToString(v.sig),
			ParamSet:  "Falcon-512",
		})
		if !vr.Success {
			t.Fatalf("test %d: 官方签名验签失败: %s", i, vr.Error)
		}

		// 篡改消息必须验签失败
		bad := FalconVerify(SLHDSAVerifyRequest{
			PublicKey: hex.EncodeToString(v.pk),
			Data:      hex.EncodeToString([]byte("tampered message")),
			Signature: hex.EncodeToString(v.sig),
			ParamSet:  "Falcon-512",
		})
		if bad.Success {
			t.Fatalf("test %d: 篡改消息竟然验签通过", i)
		}
	}
	t.Logf("FALCON-512: %d 组 KAT 向量全部通过", len(vecs))
}

func TestFalconSelfConsistency(t *testing.T) {
	msg := hex.EncodeToString([]byte("Hello, Falcon!"))
	for _, paramSet := range []string{"Falcon-512", "Falcon-1024"} {
		t.Run(paramSet, func(t *testing.T) {
			kr := FalconKeyGen(paramSet)
			if !kr.Success {
				t.Fatalf("keygen failed: %s", kr.Error)
			}

			sig := FalconSign(SLHDSARequest{
				PrivateKey: kr.PrivateKey,
				Data:       msg,
				ParamSet:   paramSet,
			})
			if !sig.Success {
				t.Fatalf("sign failed: %s", sig.Error)
			}

			vr := FalconVerify(SLHDSAVerifyRequest{
				PublicKey: kr.PublicKey,
				Data:      msg,
				Signature: sig.Data,
				ParamSet:  paramSet,
			})
			if !vr.Success {
				t.Fatalf("verify failed: %s", vr.Error)
			}

			bad := FalconVerify(SLHDSAVerifyRequest{
				PublicKey: kr.PublicKey,
				Data:      hex.EncodeToString([]byte("wrong message")),
				Signature: sig.Data,
				ParamSet:  paramSet,
			})
			if bad.Success {
				t.Fatal("modified message verified")
			}
		})
	}
}

func TestFalconParamSet(t *testing.T) {
	kr := FalconKeyGen("Falcon-256")
	if kr.Success || !strings.Contains(kr.Error, "Falcon-512") {
		t.Fatalf("unsupported parameter set should fail with supported set hint, got: %+v", kr)
	}
}
