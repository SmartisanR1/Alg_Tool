package pqc

import (
	"bufio"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// parseAigisVec 解析官方 C 实现生成的 KAT 向量文件。
func parseAigisVec(t *testing.T, path string) [][5]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开向量文件失败: %v", err)
	}
	defer f.Close()

	var vecs [][5]string
	var cur [5]string
	idx := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "TEST ") {
			if idx == 5 && cur[0] != "" {
				vecs = append(vecs, cur)
			}
			cur = [5]string{}
			idx = 0
			continue
		}
		if strings.HasPrefix(line, "TEST") || strings.HasPrefix(line, "MODE") || strings.HasPrefix(line, "PUB") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		cur[idx] = strings.TrimSpace(parts[1])
		idx++
		if idx == 5 {
			vecs = append(vecs, cur)
			cur = [5]string{}
			idx = 0
		}
	}
	return vecs
}

// TestAigisSigKAT: 与官方 C 实现（-DUSE_SHAKE 编译）的确定性向量端到端比对。
func TestAigisSigKAT(t *testing.T) {
	for mode, path := range map[int]string{
		1: "testdata/aigis_vec_1.txt",
		2: "testdata/aigis_vec_2.txt",
		3: "testdata/aigis_vec_3.txt",
	} {
		vecs := parseAigisVec(t, path)
		p := &aigisStdParamsList[mode-1]
		for i, v := range vecs {
			coins, _ := hex.DecodeString(v[0])
			wantPK, _ := hex.DecodeString(v[1])
			wantSK, _ := hex.DecodeString(v[2])
			m, _ := hex.DecodeString(v[3])
			wantSig, _ := hex.DecodeString(v[4])

			pk, sk := p.keypairInternal(coins, aigisHashSHAKE)
			if hex.EncodeToString(pk) != hex.EncodeToString(wantPK) {
				t.Fatalf("mode=%d test=%d: 公钥不匹配", mode, i)
			}
			if hex.EncodeToString(sk) != hex.EncodeToString(wantSK) {
				t.Fatalf("mode=%d test=%d: 私钥不匹配", mode, i)
			}

			sig, err := p.signInternal(sk, m, aigisHashSHAKE)
			if err != nil {
				t.Fatalf("mode=%d test=%d: 签名失败: %v", mode, i, err)
			}
			if hex.EncodeToString(sig) != hex.EncodeToString(wantSig) {
				t.Logf("mode=%d test=%d got=%s\nwant=%s", mode, i, hex.EncodeToString(sig), hex.EncodeToString(wantSig))
				t.Fatalf("mode=%d test=%d: 签名不匹配", mode, i)
			}

			if !p.verifyInternal(sig, m, pk, aigisHashSHAKE) {
				t.Fatalf("mode=%d test=%d: 官方签名验签失败", mode, i)
			}
		}
		t.Logf("mode=%d: %d 组 KAT 向量全部通过", mode, len(vecs))
	}
}

// TestAigisSigSelfConsistency: 自生成密钥对，SM3/SHAKE 双模式签-验自洽。
func TestAigisSigSelfConsistency(t *testing.T) {
	msgs := [][]byte{
		[]byte("hello aigis-sig"),
		make([]byte, 500),
	}
	for modeIdx := 1; modeIdx <= 3; modeIdx++ {
		p := &aigisStdParamsList[modeIdx-1]
		for _, hashMode := range []aigisHashMode{aigisHashSM3, aigisHashSHAKE} {
			for mi, m := range msgs {
				coins := make([]byte, 32)
				for i := range coins {
					coins[i] = byte(modeIdx*7 + mi*3 + i)
				}
				pk, sk := p.keypairInternal(coins, hashMode)
				sig, err := p.signInternal(sk, m, hashMode)
				if err != nil {
					t.Fatalf("mode=%d %v msg=%d: 签名失败: %v", modeIdx, hashMode, mi, err)
				}
				if !p.verifyInternal(sig, m, pk, hashMode) {
					t.Fatalf("mode=%d %v msg=%d: 验签失败", modeIdx, hashMode, mi)
				}
				// 篡改消息应验签失败
				bad := append([]byte{}, m...)
				if len(bad) > 0 {
					bad[0] ^= 0xFF
				} else {
					bad = []byte{1}
				}
				if p.verifyInternal(sig, bad, pk, hashMode) {
					t.Fatalf("mode=%d %v msg=%d: 篡改消息验签应失败", modeIdx, hashMode, mi)
				}
			}
		}
	}
}

// TestAigisSigAPI: 公开 API 冒烟测试（随机密钥生成 + 签名 + 验签）。
func TestAigisSigAPI(t *testing.T) {
	for _, ps := range []string{"AIGIS-sig-1", "AIGIS-sig-2", "AIGIS-sig-3", "AIGIS-sig-1-SHAKE", "AIGISSIGIII-SM3"} {
		kg := AigisKeyGen(ps)
		if !kg.Success {
			t.Fatalf("%s 密钥生成失败: %s", ps, kg.Error)
		}
		if len(kg.PrivateKey) == 0 || len(kg.PublicKey) == 0 {
			t.Fatalf("%s 密钥为空", ps)
		}
		sg := AigisSign(SLHDSARequest{PrivateKey: kg.PrivateKey, Data: "01020304", ParamSet: ps})
		if !sg.Success {
			t.Fatalf("%s 签名失败: %s", ps, sg.Error)
		}
		vf := AigisVerify(SLHDSAVerifyRequest{PublicKey: kg.PublicKey, Data: "01020304", Signature: sg.Data, ParamSet: ps})
		if !vf.Success {
			t.Fatalf("%s 验签失败: %s", ps, vf.Error)
		}
	}
}
