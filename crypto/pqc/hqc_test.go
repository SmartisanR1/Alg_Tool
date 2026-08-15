package pqc

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestHQCSelfConsistency(t *testing.T) {
	for _, paramSet := range []string{"HQC-128", "HQC-192", "HQC-256"} {
		t.Run(paramSet, func(t *testing.T) {
			kr := HQCKeyGen(paramSet)
			if !kr.Success {
				t.Fatalf("keygen failed: %s", kr.Error)
			}

			enc := HQCEncapsulate(MLKEMRequest{
				PublicKey: kr.PublicKey,
				ParamSet:  paramSet,
			})
			if !enc.Success {
				t.Fatalf("encapsulate failed: %s", enc.Error)
			}

			dec := HQCDecapsulate(MLKEMDecapRequest{
				PrivateKey: kr.PrivateKey,
				Ciphertext: enc.Ciphertext,
				ParamSet:   paramSet,
			})
			if !dec.Success {
				t.Fatalf("decapsulate failed: %s", dec.Error)
			}
			if dec.Data != enc.SharedSecret {
				t.Fatalf("shared secret mismatch")
			}
		})
	}
}

// TestHQCSizes: 校验各参数集的密钥/密文/共享密钥尺寸与 HQC 官方规范一致。
func TestHQCSizes(t *testing.T) {
	// pk / ct / ss 字节数（pk、ct 与前端参数表一致；共享密钥恒为 32B）
	want := map[string][3]int{
		"HQC-128": {2241, 4433, 32},
		"HQC-192": {4514, 8978, 32},
		"HQC-256": {7237, 14421, 32},
	}
	for paramSet, sizes := range want {
		kr := HQCKeyGen(paramSet)
		if !kr.Success {
			t.Fatalf("%s keygen failed: %s", paramSet, kr.Error)
		}
		pk := mustHexBytes(t, kr.PublicKey)
		if len(pk) != sizes[0] {
			t.Errorf("%s 公钥尺寸错误: got %d, want %d", paramSet, len(pk), sizes[0])
		}

		enc := HQCEncapsulate(MLKEMRequest{PublicKey: kr.PublicKey, ParamSet: paramSet})
		if !enc.Success {
			t.Fatalf("%s encapsulate failed: %s", paramSet, enc.Error)
		}
		ct := mustHexBytes(t, enc.Ciphertext)
		if len(ct) != sizes[1] {
			t.Errorf("%s 密文尺寸错误: got %d, want %d", paramSet, len(ct), sizes[1])
		}
		if len(mustHexBytes(t, enc.SharedSecret)) != sizes[2] {
			t.Errorf("%s 共享密钥尺寸错误", paramSet)
		}
	}
}

func TestHQCParamSet(t *testing.T) {
	kr := HQCKeyGen("HQC-64")
	if kr.Success || kr.Error == "" {
		t.Fatalf("unsupported parameter set should fail")
	}
	enc := HQCEncapsulate(MLKEMRequest{PublicKey: "00", ParamSet: "HQC-999"})
	if enc.Success || !strings.Contains(enc.Error, "HQC-128") {
		t.Fatalf("unsupported encapsulate param set should fail with hint, got: %+v", enc)
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("无效 hex: %v", err)
	}
	return b
}
