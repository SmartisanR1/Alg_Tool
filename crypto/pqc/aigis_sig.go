// aigis_sig.go — AIGIS-sig 格基数字签名算法（官方标准实现）
//
// 对齐上海交通大学 PQMagic 团队开源的官方参考实现
// （gitee.com/pqcrypto/pqmagic，sig/aigis-sig/std），
// 国密 PQC 候选算法 Aigis-sig 三组参数集：
//   - AIGIS-sig-1: q=2021377  K=4 L=3 D=13
//   - AIGIS-sig-2: q=3870721  K=5 L=4 D=14
//   - AIGIS-sig-3: q=3870721  K=6 L=5 D=14
//
// 哈希模式支持两种（与官方实现一致）：
//   - SM3（默认，国密标准，sm3_extended 扩展输出）
//   - SHAKE（shake128/shake256，可通过参数集后缀 -SHAKE 选择）
//
// 算法框架：Fiat-Shamir with Aborts；系数为正数中心化表示 [0, Q)，
// 无符号 32 位算术 + Montgomery/Barrett 约减，与 ML-DSA/Dilithium 同构。

package pqc

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/rand"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/sha3"

	"cryptokit/crypto/symmetric"
)

// ─────────────────────────────────────────────────────────────
// 哈希模式
// ─────────────────────────────────────────────────────────────

type aigisHashMode int

const (
	aigisHashSM3 aigisHashMode = iota
	aigisHashSHAKE
)

func (m aigisHashMode) String() string {
	if m == aigisHashSHAKE {
		return "SHAKE"
	}
	return "SM3"
}

// sm3Extended 实现官方 sm3_extended：SM3(BE32(nonce) || in) 按 nonce=0,1,2...
// 拼接，输出截断到 out 长度（SM3 的任意长度 XOF 扩展）。
func sm3Extended(out, in []byte) {
	var nbuf [4]byte
	for nonce := uint32(0); len(out) > 0; nonce++ {
		binary.BigEndian.PutUint32(nbuf[:], nonce)
		h := sm3.New()
		h.Write(nbuf[:])
		h.Write(in)
		sum := h.Sum(nil)
		n := copy(out, sum)
		out = out[n:]
	}
}

// ─────────────────────────────────────────────────────────────
// 参数集
// ─────────────────────────────────────────────────────────────

const aigisStdN = 256

type aigisStdParams struct {
	mode  int    // 1/2/3
	name  string // 展示名
	q     uint32 // 模量
	qbits int    // 模量位数 21/22
	d     int    // 低比特位数 13/14
	g1    uint32 // GAMMA1
	g2    uint32 // GAMMA2
	alpha uint32 // 2*GAMMA2
	k, l  int
	eta1  int
	eta2  int
	beta1 int
	beta2 int
	omega int

	mont uint32 // 2^32 mod q
	qinv uint32 // -q^{-1} mod 2^32

	zetas     [aigisStdN]uint32
	zetasInv  [aigisStdN]uint32
	montInvn  uint64
	alphaMult int // decompose 快速除法用的移位量

	// 打包大小
	polzSize     int // N*18/8
	polw1Size    int // N*3/8
	polSize      int // N*qbits/8
	polt1Size    int // N*(qbits-d)/8
	polt0Size    int // N*d/8
	poleta1Size  int // N*SETA1BITS/8
	poleta2Size  int // N*SETA2BITS/8
	pkSize       int
	skSize       int
	sigSize      int
	eta1Bits     int // 打包位宽
	eta2Bits     int
	gamma1m1Mask uint32 // 0x3FFFF
}

var aigisStdParamsList = []aigisStdParams{
	makeAigisStdParams1(),
	makeAigisStdParams2(),
	makeAigisStdParams3(),
}

// aigisZetas2021377 / aigisZetasInv2021377: q=2021377（AIGIS-sig-1）
func aigisZetas2021377() [aigisStdN]uint32 {
	return [aigisStdN]uint32{1562548, 518470, 697898, 862629, 1367459, 1539276, 1513857, 1662806, 929015, 1757045, 1879015, 449873, 75689, 1125711, 1680345, 620849, 769419, 486664, 1389778, 658915, 1319993, 73499, 1391732, 1199964, 291970, 655587, 966181, 128755, 288564, 10420, 1980158, 1011904, 1937906, 838813, 854780, 1453936, 1704819, 1740984, 86645, 1360044, 115556, 1570480, 1655800, 272433, 1245520, 1190005, 238406, 1726139, 1013693, 1948648, 1020399, 1544116, 1120075, 656153, 591869, 1620799, 275832, 517427, 1601944, 1555925, 1293833, 1705829, 1357642, 142050, 739420, 1568070, 1535360, 740638, 57925, 1038012, 65439, 1844105, 673379, 1768997, 924638, 1986117, 1394208, 1277276, 129269, 1760277, 1173604, 1161770, 1897168, 807697, 965038, 1876057, 1963820, 1794916, 924093, 251419, 168030, 1073286, 1902394, 347156, 1488477, 511116, 572755, 1686880, 268077, 53223, 1268228, 579769, 1043786, 272581, 1574784, 1729984, 568576, 276296, 1095755, 282107, 158374, 915466, 1569380, 908136, 972609, 923797, 466409, 1762448, 798650, 436051, 1275685, 1122838, 1862, 1854194, 1432015, 1507507, 1452715, 1170924, 137295, 531590, 556763, 1442250, 896280, 320184, 333460, 1993546, 622613, 1352919, 881664, 1176558, 1936677, 2011958, 1357750, 534023, 142791, 40293, 638104, 1519860, 1189220, 1763667, 792470, 1813814, 830483, 1256948, 1537350, 64760, 561409, 823180, 786453, 1106713, 1491299, 1582163, 822179, 1663832, 1269819, 84100, 780824, 310495, 1043416, 763923, 1440072, 1308437, 1369984, 1027053, 641681, 932722, 1248044, 318540, 1777818, 702544, 1566714, 1301662, 265980, 696370, 1576958, 449193, 1228202, 1635455, 1143957, 1349609, 120737, 1115065, 1815624, 573533, 10820, 1911846, 533321, 1147868, 1126927, 145151, 641139, 275750, 276830, 1257214, 988074, 1857331, 105366, 1608247, 1752751, 817865, 294374, 1145376, 1447053, 647982, 1517128, 301974, 233775, 1669708, 1146108, 1913137, 707228, 1147423, 349817, 1972001, 777351, 1874015, 964313, 161863, 1142539, 1331457, 1604014, 1320129, 1103939, 1236477, 447210, 1613614, 1666811, 51306, 383284, 1573619, 677023, 994549, 23785, 210391, 461525, 1779756, 430663, 84620, 1731642, 1784991, 147098, 942182, 1953450, 1853187, 1567373, 1541031}
}

func aigisZetasInv2021377() [aigisStdN]uint32 {
	return [aigisStdN]uint32{480346, 454004, 168190, 67927, 1079195, 1874279, 236386, 289735, 1936757, 1590714, 241621, 1559852, 1810986, 1997592, 1026828, 1344354, 447758, 1638093, 1970071, 354566, 407763, 1574167, 784900, 917438, 701248, 417363, 689920, 878838, 1859514, 1057064, 147362, 1244026, 49376, 1671560, 873954, 1314149, 108240, 875269, 351669, 1787602, 1719403, 504249, 1373395, 574324, 876001, 1727003, 1203512, 268626, 413130, 1916011, 164046, 1033303, 764163, 1744547, 1745627, 1380238, 1876226, 894450, 873509, 1488056, 109531, 2010557, 1447844, 205753, 906312, 1900640, 671768, 877420, 385922, 793175, 1572184, 444419, 1325007, 1755397, 719715, 454663, 1318833, 243559, 1702837, 773333, 1088655, 1379696, 994324, 651393, 712940, 581305, 1257454, 977961, 1710882, 1240553, 1937277, 751558, 357545, 1199198, 439214, 530078, 914664, 1234924, 1198197, 1459968, 1956617, 484027, 764429, 1190894, 207563, 1228907, 257710, 832157, 501517, 1383273, 1981084, 1878586, 1487354, 663627, 9419, 84700, 844819, 1139713, 668458, 1398764, 27831, 1687917, 1701193, 1125097, 579127, 1464614, 1489787, 1884082, 850453, 568662, 513870, 589362, 167183, 2019515, 898539, 745692, 1585326, 1222727, 258929, 1554968, 1097580, 1048768, 1113241, 451997, 1105911, 1863003, 1739270, 925622, 1745081, 1452801, 291393, 446593, 1748796, 977591, 1441608, 753149, 1968154, 1753300, 334497, 1448622, 1510261, 532900, 1674221, 118983, 948091, 1853347, 1769958, 1097284, 226461, 57557, 145320, 1056339, 1213680, 124209, 859607, 847773, 261100, 1892108, 744101, 627169, 35260, 1096739, 252380, 1347998, 177272, 1955938, 983365, 1963452, 1280739, 486017, 453307, 1281957, 1879327, 663735, 315548, 727544, 465452, 419433, 1503950, 1745545, 400578, 1429508, 1365224, 901302, 477261, 1000978, 72729, 1007684, 295238, 1782971, 831372, 775857, 1748944, 365577, 450897, 1905821, 661333, 1934732, 280393, 316558, 567441, 1166597, 1182564, 83471, 1009473, 41219, 2010957, 1732813, 1892622, 1055196, 1365790, 1729407, 821413, 629645, 1947878, 701384, 1362462, 631599, 1534713, 1251958, 1400528, 341032, 895666, 1945688, 1571504, 142362, 264332, 1092362, 358571, 507520, 482101, 653918, 1158748, 1323479, 1331599}
}

// aigisZetas3870721 / aigisZetasInv3870721: q=3870721（AIGIS-sig-2/3）
func aigisZetas3870721() [aigisStdN]uint32 {
	return [aigisStdN]uint32{2337707, 2505409, 267692, 529914, 420735, 181988, 2608440, 3865338, 3665767, 288746, 2524026, 3008396, 901579, 70491, 1821213, 1437514, 3375394, 502705, 3475623, 3513653, 1833017, 3651222, 947790, 1966036, 2704588, 2850143, 3030905, 1622520, 3210245, 3127826, 292206, 3096784, 3201921, 3867412, 1705316, 2917474, 2975359, 2004421, 2812268, 890313, 2511631, 3623292, 2803099, 2903766, 1596209, 2040136, 3468632, 2156661, 2913824, 2560388, 1214035, 3468039, 575792, 2926910, 3407464, 2292204, 2285761, 2338667, 63216, 3835938, 3204529, 1818443, 3786633, 3241498, 944328, 616348, 2927622, 64038, 1171534, 1361903, 2827360, 3144828, 2738981, 1714811, 3625146, 89505, 2787809, 2363190, 2513795, 3306399, 1418851, 1206903, 926563, 211044, 466372, 3410093, 1353383, 3610570, 934100, 2471859, 2037600, 2996463, 1698492, 525418, 1662944, 1981925, 1210222, 1813802, 314420, 2466015, 3516872, 3320431, 1355971, 1500137, 493991, 36365, 3235243, 214827, 2544017, 1739057, 945221, 1038283, 2889903, 3364214, 1674857, 1434035, 1665177, 2651227, 1575769, 1155464, 467835, 1713031, 2041544, 408424, 137443, 2029527, 2115209, 2293884, 2137416, 3189891, 2471629, 2229785, 2611740, 2394735, 2287191, 2862622, 300090, 1004990, 401830, 143957, 2910193, 3787906, 3628164, 3171269, 2239135, 3038465, 601725, 2887353, 2766912, 1622354, 2989501, 1339396, 1939160, 2386893, 103181, 2793304, 911193, 3295333, 3025653, 2513246, 314427, 939239, 57676, 2293294, 2833811, 2842292, 3139575, 2705158, 1290463, 3780876, 1462003, 668827, 1850975, 2327221, 2910099, 2724881, 418972, 957090, 321362, 2898276, 3523069, 1463158, 3818473, 453440, 1891547, 1601731, 529312, 3301251, 1117070, 3520718, 634170, 1958581, 929634, 1133255, 3807619, 1159272, 3292496, 3530590, 927442, 3686531, 2605292, 384058, 1415774, 1040397, 3663661, 2332173, 1131260, 680774, 1186917, 3736575, 1064994, 2954460, 3051663, 1162037, 2962553, 2130376, 1717870, 3565361, 2935922, 2347272, 1768863, 3125776, 1686747, 3137894, 2993356, 1574419, 1073008, 1262182, 183934, 914847, 3373156, 3688758, 2538361, 614066, 3211143, 3565127, 1322591, 3426188, 2951336, 172348, 3747492, 3719872, 2962113, 778168, 2880082, 1051508, 3741079, 1816757, 763621, 328987, 2831790, 1276220, 135870, 3388537, 3034187, 2419032}
}

func aigisZetasInv3870721() [aigisStdN]uint32 {
	return [aigisStdN]uint32{1451689, 836534, 482184, 3734851, 2594501, 1038931, 3541734, 3107100, 2053964, 129642, 2819213, 990639, 3092553, 908608, 150849, 123229, 3698373, 919385, 444533, 2548130, 305594, 659578, 3256655, 1332360, 181963, 497565, 2955874, 3686787, 2608539, 2797713, 2296302, 877365, 732827, 2183974, 744945, 2101858, 1523449, 934799, 305360, 2152851, 1740345, 908168, 2708684, 819058, 916261, 2805727, 134146, 2683804, 3189947, 2739461, 1538548, 207060, 2830324, 2454947, 3486663, 1265429, 184190, 2943279, 340131, 578225, 2711449, 63102, 2737466, 2941087, 1912140, 3236551, 350003, 2753651, 569470, 3341409, 2268990, 1979174, 3417281, 52248, 2407563, 347652, 972445, 3549359, 2913631, 3451749, 1145840, 960622, 1543500, 2019746, 3201894, 2408718, 89845, 2580258, 1165563, 731146, 1028429, 1036910, 1577427, 3813045, 2931482, 3556294, 1357475, 845068, 575388, 2959528, 1077417, 3767540, 1483828, 1931561, 2531325, 881220, 2248367, 1103809, 983368, 3268996, 832256, 1631586, 699452, 242557, 82815, 960528, 3726764, 3468891, 2865731, 3570631, 1008099, 1583530, 1475986, 1258981, 1640936, 1399092, 680830, 1733305, 1576837, 1755512, 1841194, 3733278, 3462297, 1829177, 2157690, 3402886, 2715257, 2294952, 1219494, 2205544, 2436686, 2195864, 506507, 980818, 2832438, 2925500, 2131664, 1326704, 3655894, 635478, 3834356, 3376730, 2370584, 2514750, 550290, 353849, 1404706, 3556301, 2056919, 2660499, 1888796, 2207777, 3345303, 2172229, 874258, 1833121, 1398862, 2936621, 260151, 2517338, 460628, 3404349, 3659677, 2944158, 2663818, 2451870, 564322, 1356926, 1507531, 1082912, 3781216, 245575, 2155910, 1131740, 725893, 1043361, 2508818, 2699187, 3806683, 943099, 3254373, 2926393, 629223, 84088, 2052278, 666192, 34783, 3807505, 1532054, 1584960, 1578517, 463257, 943811, 3294929, 402682, 2656686, 1310333, 956897, 1714060, 402089, 1830585, 2274512, 966955, 1067622, 247429, 1359090, 2980408, 1058453, 1866300, 895362, 953247, 2165405, 3309, 668800, 773937, 3578515, 742895, 660476, 2248201, 839816, 1020578, 1166133, 1904685, 2922931, 219499, 2037704, 357068, 395098, 3368016, 495327, 2433207, 2049508, 3800230, 2969142, 862325, 1346695, 3581975, 204954, 5383, 1262281, 3688733, 3449986, 3340807, 3603029, 951197}
}

func makeAigisStdParams1() aigisStdParams {
	p := aigisStdParams{
		mode: 1, name: "AIGIS-sig-1",
		q: 2021377, qbits: 21, d: 13,
		g1: 131072, g2: 168448,
		k: 4, l: 3, eta1: 2, eta2: 3,
		beta1: 120, beta2: 175, omega: 80,
		mont: 1562548, qinv: 2849953791,
	}
	p.alpha = 2 * p.g2
	p.alphaMult = 20
	p.gamma1m1Mask = 0x3FFFF
	p.zetas = aigisZetas2021377()
	p.zetasInv = aigisZetasInv2021377()
	p.finishParams()
	return p
}

func makeAigisStdParams2() aigisStdParams {
	p := aigisStdParams{
		mode: 2, name: "AIGIS-sig-2",
		q: 3870721, qbits: 22, d: 14,
		g1: 131072, g2: 322560,
		k: 5, l: 4, eta1: 2, eta2: 5,
		beta1: 120, beta2: 275, omega: 96,
		mont: 2337707, qinv: 2671448063,
	}
	p.alpha = 2 * p.g2
	p.alphaMult = 21
	p.gamma1m1Mask = 0x3FFFF
	p.zetas = aigisZetas3870721()
	p.zetasInv = aigisZetasInv3870721()
	p.finishParams()
	return p
}

func makeAigisStdParams3() aigisStdParams {
	p := aigisStdParams{
		mode: 3, name: "AIGIS-sig-3",
		q: 3870721, qbits: 22, d: 14,
		g1: 131072, g2: 322560,
		k: 6, l: 5, eta1: 1, eta2: 5,
		beta1: 60, beta2: 275, omega: 120,
		mont: 2337707, qinv: 2671448063,
	}
	p.alpha = 2 * p.g2
	p.alphaMult = 21
	p.gamma1m1Mask = 0x3FFFF
	p.zetas = aigisZetas3870721()
	p.zetasInv = aigisZetasInv3870721()
	p.finishParams()
	return p
}

func (p *aigisStdParams) finishParams() {
	p.polzSize = aigisStdN * 18 / 8
	p.polw1Size = aigisStdN * 3 / 8
	p.polSize = aigisStdN * p.qbits / 8
	p.polt1Size = aigisStdN * (p.qbits - p.d) / 8
	p.polt0Size = aigisStdN * p.d / 8
	if p.eta1 == 1 {
		p.eta1Bits = 2
	} else {
		p.eta1Bits = 3
	}
	if p.eta2 <= 3 {
		p.eta2Bits = 3
	} else {
		p.eta2Bits = 4
	}
	p.poleta1Size = aigisStdN * p.eta1Bits / 8
	p.poleta2Size = aigisStdN * p.eta2Bits / 8
	p.pkSize = 32 + p.k*p.polt1Size
	p.skSize = 2*32 + p.l*p.poleta1Size + p.k*p.poleta2Size + 48 + p.k*p.polt0Size
	p.sigSize = p.l*p.polzSize + (p.omega + p.k) + (aigisStdN/8 + 8)
	// mont_invn = (MONT*MONT % Q * (Q-1) % Q) * ((Q-1) >> 8) % Q
	m := uint64(p.mont) * uint64(p.mont) % uint64(p.q)
	m = m * uint64(p.q-1) % uint64(p.q)
	p.montInvn = m * uint64((p.q-1)>>8) % uint64(p.q)
}

func (p *aigisStdParams) hash(out, in []byte, mode aigisHashMode) {
	if mode == aigisHashSHAKE {
		sha3.ShakeSum256(out, in)
	} else {
		sm3Extended(out, in)
	}
}

// ─────────────────────────────────────────────────────────────
// 约减 (reduce.c)
// ─────────────────────────────────────────────────────────────

// montReduce: 输入 a ≤ Q*2^32，输出 < 2*Q
func (p *aigisStdParams) montReduce(a uint64) uint32 {
	t := a * uint64(p.qinv)
	t &= 0xFFFFFFFF
	t *= uint64(p.q)
	t += a
	return uint32(t >> 32)
}

// barratReduce: 输入 a < 12Q(或 27Q)，输出 < 2Q
func (p *aigisStdParams) barratReduce(a uint32) uint32 {
	t := a >> uint(p.qbits)
	t *= p.q
	return a - t
}

// freeze2q: 输入 a < 2Q，输出 < Q
func (p *aigisStdParams) freeze2q(a uint32) uint32 {
	a -= p.q
	a += uint32(int32(a)>>31) & p.q
	return a
}

// freeze4q: 输入 a < 4Q，输出 < Q
func (p *aigisStdParams) freeze4q(a uint32) uint32 {
	a -= 2 * p.q
	a += uint32(int32(a)>>31) & (2 * p.q)
	a -= p.q
	a += uint32(int32(a)>>31) & p.q
	return a
}

// ─────────────────────────────────────────────────────────────
// NTT (ntt.c)
// ─────────────────────────────────────────────────────────────

func (p *aigisStdParams) ntt(poly []uint32) {
	k := 1
	for length := 128; length > 0; length >>= 1 {
		for start := 0; start < aigisStdN; start += 2 * length {
			zeta := p.zetas[k]
			k++
			for j := start; j < start+length; j++ {
				t := p.montReduce(uint64(zeta) * uint64(poly[j+length]))
				poly[j+length] = poly[j] + 2*p.q - t
				poly[j] = poly[j] + t
			}
		}
	}
}

// invnttFromInvMont: 逆 NTT 并乘 Montgomery 因子 2^32；
// 输入 < 4Q，输出 < 2Q
func (p *aigisStdParams) invnttFromInvMont(poly []uint32) {
	k := 0
	for length := 1; length < aigisStdN; length <<= 1 {
		for start := 0; start < aigisStdN; start += 2 * length {
			zeta := p.zetasInv[k]
			k++
			for j := start; j < start+length; j++ {
				t := poly[j]
				poly[j] = t + poly[j+length]
				poly[j+length] = t + 512*p.q - poly[j+length]
				poly[j+length] = p.montReduce(uint64(zeta) * uint64(poly[j+length]))
			}
		}
	}
	for j := 0; j < aigisStdN/2; j++ {
		poly[j] = p.montReduce(p.montInvn * uint64(poly[j]))
	}
}

// ─────────────────────────────────────────────────────────────
// 舍入 (rounding.c)
// ─────────────────────────────────────────────────────────────

func (p *aigisStdParams) power2round(a uint32) (a1, a0 uint32) {
	t := int32(a & ((1 << uint(p.d)) - 1))
	t -= int32(1<<uint(p.d-1)) + 1
	t += (t >> 31) & int32(1<<uint(p.d))
	t -= int32(1<<uint(p.d-1)) - 1
	a0 = uint32(int32(p.q) + t)
	a1 = (a - uint32(t)) >> uint(p.d)
	return a1, a0
}

func (p *aigisStdParams) decompose(a uint32) (a1, a0 uint32) {
	var u, t int64
	u = (int64(a) * 3 >> uint(p.alphaMult)) + 1
	t = int64(a) - u*int64(p.alpha)
	if t < 0 {
		u--
		t += int64(p.alpha)
	}
	t -= int64(p.alpha)/2 + 1
	if t < 0 {
		t += int64(p.alpha)
	}
	t -= int64(p.alpha)/2 - 1

	a1 = uint32(u)
	if t < 0 {
		a1++
	}
	if a1 == 6 {
		a0 = uint32(int32(p.q) + int32(t) - 1)
		a1 = 0
	} else {
		a0 = uint32(int32(p.q) + int32(t))
	}
	return a1, a0
}

func (p *aigisStdParams) makeHint(a, b uint32) uint32 {
	a1a, _ := p.decompose(a)
	a1b, _ := p.decompose(p.freeze4q(a + b))
	if a1a != a1b {
		return 1
	}
	return 0
}

func (p *aigisStdParams) useHint(a uint32, hint uint32) uint32 {
	a1, a0 := p.decompose(a)
	if hint == 0 {
		return a1
	}
	halfQalpha := (p.q - 1) / p.alpha
	if a0 > p.q {
		if a1 == halfQalpha-1 {
			return 0
		}
		return a1 + 1
	}
	if a1 == 0 {
		return halfQalpha - 1
	}
	return a1 - 1
}

// ─────────────────────────────────────────────────────────────
// 多项式 (poly.c)
// ─────────────────────────────────────────────────────────────

type aigisStdPoly struct {
	coeffs [aigisStdN]uint32
}

func (p *aigisStdParams) polyAdd(c, a, b *aigisStdPoly) {
	for i := 0; i < aigisStdN; i++ {
		c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
	}
}

func (p *aigisStdParams) polySub(c, a, b *aigisStdPoly) {
	for i := 0; i < aigisStdN; i++ {
		c.coeffs[i] = a.coeffs[i] + 2*p.q - b.coeffs[i]
	}
}

func (p *aigisStdParams) polyNeg(a *aigisStdPoly) {
	for i := 0; i < aigisStdN; i++ {
		a.coeffs[i] = 2*p.q - a.coeffs[i]
	}
}

func (p *aigisStdParams) polyShiftl(a *aigisStdPoly, k uint) {
	for i := 0; i < aigisStdN; i++ {
		a.coeffs[i] <<= k
	}
}

func (p *aigisStdParams) polyFreeze2q(a *aigisStdPoly) {
	for i := 0; i < aigisStdN; i++ {
		a.coeffs[i] = p.freeze2q(a.coeffs[i])
	}
}

func (p *aigisStdParams) polyFreeze4q(a *aigisStdPoly) {
	for i := 0; i < aigisStdN; i++ {
		a.coeffs[i] = p.freeze4q(a.coeffs[i])
	}
}

func (p *aigisStdParams) polyNTT(a *aigisStdPoly) {
	p.ntt(a.coeffs[:])
}

func (p *aigisStdParams) polyInvNTTMont(a *aigisStdPoly) {
	p.invnttFromInvMont(a.coeffs[:])
}

func (p *aigisStdParams) polyPointwiseInvMont(c, a, b *aigisStdPoly) {
	for i := 0; i < aigisStdN; i++ {
		c.coeffs[i] = p.montReduce(uint64(a.coeffs[i]) * uint64(b.coeffs[i]))
	}
}

func (p *aigisStdParams) polyChkNORM(a *aigisStdPoly, B uint32) bool {
	halfQ := (p.q - 1) / 2
	for i := 0; i < aigisStdN; i++ {
		t := int32(halfQ) - int32(a.coeffs[i])
		t ^= t >> 31
		t = int32(halfQ) - t
		if uint32(t) >= B {
			return true
		}
	}
	return false
}

// rejEta1: eta1=1 时 2-bit/系数（每字节 4 个），eta1=2 时 3-bit/系数（每 3 字节 8 个）
func (p *aigisStdParams) rejEta1(dst []uint32, buf []byte) {
	ctr := 0
	pos := 0
	var t [8]uint32
	if p.eta1 == 1 {
		// ETA1 == 1: 每字节 4 个 2-bit 采样
		for ctr < aigisStdN-4 {
			b := buf[pos]
			pos++
			t[0] = uint32(b) & 0x03
			t[1] = (uint32(b) >> 2) & 0x03
			t[2] = (uint32(b) >> 4) & 0x03
			t[3] = (uint32(b) >> 6) & 0x03
			for j := 0; j < 4; j++ {
				if t[j] <= 2*uint32(p.eta1) {
					dst[ctr] = p.q + uint32(p.eta1) - t[j]
					ctr++
				}
			}
		}
		for ctr < aigisStdN {
			b := buf[pos]
			pos++
			t[0] = uint32(b) & 0x03
			t[1] = (uint32(b) >> 2) & 0x03
			t[2] = (uint32(b) >> 4) & 0x03
			t[3] = (uint32(b) >> 6) & 0x03
			for j := 0; j < 4; j++ {
				if t[j] <= 2*uint32(p.eta1) && ctr < aigisStdN {
					dst[ctr] = p.q + uint32(p.eta1) - t[j]
					ctr++
				}
			}
		}
		return
	}
	// ETA1 == 2: 每 3 字节 8 个 3-bit 采样
	for ctr < aigisStdN-8 {
		t[0] = uint32(buf[pos]) & 0x07
		t[1] = (uint32(buf[pos]) >> 3) & 0x07
		t[2] = (uint32(buf[pos]) >> 6) | (uint32(buf[pos+1])&0x01)<<2
		t[3] = (uint32(buf[pos+1]) >> 1) & 0x07
		t[4] = (uint32(buf[pos+1]) >> 4) & 0x07
		t[5] = (uint32(buf[pos+1]) >> 7) | (uint32(buf[pos+2])&0x03)<<1
		t[6] = (uint32(buf[pos+2]) >> 2) & 0x07
		t[7] = uint32(buf[pos+2]) >> 5
		pos += 3
		for j := 0; j < 8; j++ {
			if t[j] <= 2*uint32(p.eta1) {
				dst[ctr] = p.q + uint32(p.eta1) - t[j]
				ctr++
			}
		}
	}
	for ctr < aigisStdN {
		t[0] = uint32(buf[pos]) & 0x07
		t[1] = (uint32(buf[pos]) >> 3) & 0x07
		t[2] = (uint32(buf[pos]) >> 6) | (uint32(buf[pos+1])&0x01)<<2
		t[3] = (uint32(buf[pos+1]) >> 1) & 0x07
		t[4] = (uint32(buf[pos+1]) >> 4) & 0x07
		t[5] = (uint32(buf[pos+1]) >> 7) | (uint32(buf[pos+2])&0x03)<<1
		t[6] = (uint32(buf[pos+2]) >> 2) & 0x07
		t[7] = uint32(buf[pos+2]) >> 5
		pos += 3
		for j := 0; j < 8; j++ {
			if t[j] <= 2*uint32(p.eta1) && ctr < aigisStdN {
				dst[ctr] = p.q + uint32(p.eta1) - t[j]
				ctr++
			}
		}
	}
}

// rejEta2: 返回已消耗字节数 pos
func (p *aigisStdParams) rejEta2(dst []uint32, length int, buf []byte) int {
	ctr := 0
	pos := 0
	var t0, t1 uint32
	eta2 := uint32(2 * p.eta2)
	qEta2 := p.q + uint32(p.eta2)
	if p.eta2 == 3 {
		// 每字节 2 个 3-bit 采样（t0=低3位, t1=高3位）
		for ctr < length-2 {
			b := uint32(buf[pos])
			pos++
			t0 = b & 0x07
			t1 = b >> 5
			if t0 <= eta2 {
				dst[ctr] = qEta2 - t0
				ctr++
			}
			if t1 <= eta2 {
				dst[ctr] = qEta2 - t1
				ctr++
			}
		}
		for ctr < length {
			b := uint32(buf[pos])
			pos++
			t0 = b & 0x07
			t1 = b >> 5
			if t0 <= eta2 {
				dst[ctr] = qEta2 - t0
				ctr++
			}
			if t1 <= eta2 && ctr < length {
				dst[ctr] = qEta2 - t1
				ctr++
			}
		}
		return pos
	}
	// ETA2 == 5: 每字节 2 个 4-bit 采样
	for ctr < length-2 {
		b := uint32(buf[pos])
		pos++
		t0 = b & 0x0F
		t1 = b >> 4
		if t0 <= eta2 {
			dst[ctr] = qEta2 - t0
			ctr++
		}
		if t1 <= eta2 {
			dst[ctr] = qEta2 - t1
			ctr++
		}
	}
	for ctr < length {
		b := uint32(buf[pos])
		pos++
		t0 = b & 0x0F
		t1 = b >> 4
		if t0 <= eta2 {
			dst[ctr] = qEta2 - t0
			ctr++
		}
		if t1 <= eta2 && ctr < length {
			dst[ctr] = qEta2 - t1
			ctr++
		}
	}
	return pos
}

func (p *aigisStdParams) polyUniformEta1(a *aigisStdPoly, seed []byte, nonce byte, mode aigisHashMode) {
	inbuf := make([]byte, 32+2)
	copy(inbuf, seed)
	inbuf[32] = nonce
	outbuf := make([]byte, 2*136)
	if mode == aigisHashSHAKE {
		sha3.ShakeSum256(outbuf, inbuf[:33])
	} else {
		inbuf[33] = 0
		sm3Extended(outbuf, inbuf[:34])
	}
	p.rejEta1(a.coeffs[:], outbuf)
}

func (p *aigisStdParams) polyUniformEta2(a *aigisStdPoly, seed []byte, nonce byte, mode aigisHashMode) {
	inbuf := make([]byte, 32+2)
	copy(inbuf, seed)
	inbuf[32] = nonce
	outbuf := make([]byte, 3*136)
	var pos int
	if p.eta2 == 3 {
		// 256 个系数，2 块（272 字节）足够
		if mode == aigisHashSHAKE {
			sha3.ShakeSum256(outbuf[:2*136], inbuf[:33])
		} else {
			inbuf[33] = 0
			sm3Extended(outbuf[:2*136], inbuf[:34])
		}
		p.rejEta2(a.coeffs[:], aigisStdN, outbuf)
		return
	}
	// ETA2 == 5: 前 223 个系数
	if mode == aigisHashSHAKE {
		h := sha3.NewShake256()
		h.Write(inbuf[:33])
		h.Read(outbuf[:2*136])
		pos = p.rejEta2(a.coeffs[:223], 223, outbuf)
		if 2*136-pos < 85 {
			h.Read(outbuf[2*136 : 3*136])
		}
	} else {
		inbuf[33] = 0
		sm3Extended(outbuf[:2*136], inbuf[:34])
		pos = p.rejEta2(a.coeffs[:223], 223, outbuf)
		if 2*136-pos < 85 {
			inbuf[33] = 1
			sm3Extended(outbuf[2*136:3*136], inbuf[:34])
		}
	}
	// 剩余 33 个系数
	p.rejEta2(a.coeffs[223:], 33, outbuf[pos:])
}

func (p *aigisStdParams) polyUniformGamma1m1(a *aigisStdPoly, seed []byte, nonce uint16, mode aigisHashMode) {
	inbuf := make([]byte, len(seed)+2)
	copy(inbuf, seed)
	inbuf[len(seed)] = byte(nonce)
	inbuf[len(seed)+1] = byte(nonce >> 8)
	outbuf := make([]byte, 5*136)
	if mode == aigisHashSHAKE {
		sha3.ShakeSum256(outbuf, inbuf)
	} else {
		sm3Extended(outbuf, inbuf)
	}
	ctr := 0
	pos := 0
	var t0, t1 uint32
	mask := p.gamma1m1Mask
	twoG1 := 2 * p.g1
	g1m1 := p.g1 - 1
	qPlus := p.q + g1m1
	for ctr < aigisStdN-2 {
		t0 = uint32(outbuf[pos])
		t0 |= uint32(outbuf[pos+1]) << 8
		t0 |= uint32(outbuf[pos+2]) << 16
		t1 = uint32(outbuf[pos+2]) >> 4
		t1 |= uint32(outbuf[pos+3]) << 4
		t1 |= uint32(outbuf[pos+4]) << 12
		pos += 5
		t0 &= mask
		t1 &= mask
		if t0 <= twoG1 {
			a.coeffs[ctr] = qPlus - t0
			ctr++
		}
		if t1 <= twoG1 {
			a.coeffs[ctr] = qPlus - t1
			ctr++
		}
	}
	for ctr < aigisStdN {
		t0 = uint32(outbuf[pos])
		t0 |= uint32(outbuf[pos+1]) << 8
		t0 |= uint32(outbuf[pos+2]) << 16
		t1 = uint32(outbuf[pos+2]) >> 4
		t1 |= uint32(outbuf[pos+3]) << 4
		t1 |= uint32(outbuf[pos+4]) << 12
		pos += 5
		t0 &= mask
		t1 &= mask
		if t0 <= twoG1 {
			a.coeffs[ctr] = qPlus - t0
			ctr++
		}
		if t1 <= twoG1 && ctr < aigisStdN {
			a.coeffs[ctr] = qPlus - t1
			ctr++
		}
	}
}

// ─────────────────────────────────────────────────────────────
// 多项式打包 (poly.c packing)
// ─────────────────────────────────────────────────────────────

func (p *aigisStdParams) polyEta1Pack(r []byte, a *aigisStdPoly) {
	qEta1 := p.q + uint32(p.eta1)
	if p.eta1 == 1 {
		for i := 0; i < aigisStdN/4; i++ {
			t0 := qEta1 - a.coeffs[4*i+0]
			t1 := qEta1 - a.coeffs[4*i+1]
			t2 := qEta1 - a.coeffs[4*i+2]
			t3 := qEta1 - a.coeffs[4*i+3]
			r[i] = byte(t0 | (t1 << 2) | (t2 << 4) | (t3 << 6))
		}
		return
	}
	var t [8]uint32
	for i := 0; i < aigisStdN/8; i++ {
		for j := 0; j < 8; j++ {
			t[j] = qEta1 - a.coeffs[8*i+j]
		}
		r[3*i+0] = byte(t[0])
		r[3*i+0] |= byte(t[1] << 3)
		r[3*i+0] |= byte(t[2] << 6)
		r[3*i+1] = byte(t[2] >> 2)
		r[3*i+1] |= byte(t[3] << 1)
		r[3*i+1] |= byte(t[4] << 4)
		r[3*i+1] |= byte(t[5] << 7)
		r[3*i+2] = byte(t[5] >> 1)
		r[3*i+2] |= byte(t[6] << 2)
		r[3*i+2] |= byte(t[7] << 5)
	}
}

func (p *aigisStdParams) polyEta1Unpack(a *aigisStdPoly, r []byte) {
	qEta1 := p.q + uint32(p.eta1)
	if p.eta1 == 1 {
		for i := 0; i < aigisStdN/4; i++ {
			b := r[i]
			a.coeffs[4*i+0] = qEta1 - uint32(b&0x03)
			a.coeffs[4*i+1] = qEta1 - uint32((b>>2)&0x03)
			a.coeffs[4*i+2] = qEta1 - uint32((b>>4)&0x03)
			a.coeffs[4*i+3] = qEta1 - uint32(b>>6)
		}
		return
	}
	for i := 0; i < aigisStdN/8; i++ {
		b0 := r[3*i+0]
		b1 := r[3*i+1]
		b2 := r[3*i+2]
		a.coeffs[8*i+0] = qEta1 - uint32(b0&0x07)
		a.coeffs[8*i+1] = qEta1 - uint32((b0>>3)&0x07)
		a.coeffs[8*i+2] = qEta1 - uint32((b0>>6)|((b1&0x01)<<2))
		a.coeffs[8*i+3] = qEta1 - uint32((b1>>1)&0x07)
		a.coeffs[8*i+4] = qEta1 - uint32((b1>>4)&0x07)
		a.coeffs[8*i+5] = qEta1 - uint32((b1>>7)|((b2&0x03)<<1))
		a.coeffs[8*i+6] = qEta1 - uint32((b2>>2)&0x07)
		a.coeffs[8*i+7] = qEta1 - uint32(b2>>5)
	}
}

func (p *aigisStdParams) polyEta2Pack(r []byte, a *aigisStdPoly) {
	qEta2 := p.q + uint32(p.eta2)
	if p.eta2 <= 3 {
		var t [8]uint32
		for i := 0; i < aigisStdN/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = qEta2 - a.coeffs[8*i+j]
			}
			r[3*i+0] = byte(t[0])
			r[3*i+0] |= byte(t[1] << 3)
			r[3*i+0] |= byte(t[2] << 6)
			r[3*i+1] = byte(t[2] >> 2)
			r[3*i+1] |= byte(t[3] << 1)
			r[3*i+1] |= byte(t[4] << 4)
			r[3*i+1] |= byte(t[5] << 7)
			r[3*i+2] = byte(t[5] >> 1)
			r[3*i+2] |= byte(t[6] << 2)
			r[3*i+2] |= byte(t[7] << 5)
		}
		return
	}
	for i := 0; i < aigisStdN/2; i++ {
		t0 := qEta2 - a.coeffs[2*i+0]
		t1 := qEta2 - a.coeffs[2*i+1]
		r[i] = byte(t0 | (t1 << 4))
	}
}

func (p *aigisStdParams) polyEta2Unpack(a *aigisStdPoly, r []byte) {
	qEta2 := p.q + uint32(p.eta2)
	if p.eta2 <= 3 {
		for i := 0; i < aigisStdN/8; i++ {
			b0 := r[3*i+0]
			b1 := r[3*i+1]
			b2 := r[3*i+2]
			a.coeffs[8*i+0] = qEta2 - uint32(b0&0x07)
			a.coeffs[8*i+1] = qEta2 - uint32((b0>>3)&0x07)
			a.coeffs[8*i+2] = qEta2 - uint32((b0>>6)|((b1&0x01)<<2))
			a.coeffs[8*i+3] = qEta2 - uint32((b1>>1)&0x07)
			a.coeffs[8*i+4] = qEta2 - uint32((b1>>4)&0x07)
			a.coeffs[8*i+5] = qEta2 - uint32((b1>>7)|((b2&0x03)<<1))
			a.coeffs[8*i+6] = qEta2 - uint32((b2>>2)&0x07)
			a.coeffs[8*i+7] = qEta2 - uint32(b2>>5)
		}
		return
	}
	for i := 0; i < aigisStdN/2; i++ {
		b := r[i]
		a.coeffs[2*i+0] = qEta2 - uint32(b&0x0F)
		a.coeffs[2*i+1] = qEta2 - uint32(b>>4)
	}
}

func (p *aigisStdParams) polyT1Pack(r []byte, a *aigisStdPoly) {
	for i := 0; i < aigisStdN; i++ {
		r[i] = byte(a.coeffs[i])
	}
}

func (p *aigisStdParams) polyT1Unpack(a *aigisStdPoly, r []byte) {
	for i := 0; i < aigisStdN; i++ {
		a.coeffs[i] = uint32(r[i])
	}
}

func (p *aigisStdParams) polyT0Pack(r []byte, a *aigisStdPoly) {
	qOff := p.q + uint32(1<<uint(p.d-1))
	if p.d == 13 {
		var t [8]uint32
		for i := 0; i < aigisStdN/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = qOff - a.coeffs[8*i+j]
			}
			r[13*i+0] = byte(t[0])
			r[13*i+1] = byte(t[0] >> 8)
			r[13*i+1] |= byte(t[1] << 5)
			r[13*i+2] = byte(t[1] >> 3)
			r[13*i+3] = byte(t[1] >> 11)
			r[13*i+3] |= byte(t[2] << 2)
			r[13*i+4] = byte(t[2] >> 6)
			r[13*i+4] |= byte(t[3] << 7)
			r[13*i+5] = byte(t[3] >> 1)
			r[13*i+6] = byte(t[3] >> 9)
			r[13*i+6] |= byte(t[4] << 4)
			r[13*i+7] = byte(t[4] >> 4)
			r[13*i+8] = byte(t[4] >> 12)
			r[13*i+8] |= byte(t[5] << 1)
			r[13*i+9] = byte(t[5] >> 7)
			r[13*i+9] |= byte(t[6] << 6)
			r[13*i+10] = byte(t[6] >> 2)
			r[13*i+11] = byte(t[6] >> 10)
			r[13*i+11] |= byte(t[7] << 3)
			r[13*i+12] = byte(t[7] >> 5)
		}
		return
	}
	var t [4]uint32
	for i := 0; i < aigisStdN/4; i++ {
		for j := 0; j < 4; j++ {
			t[j] = qOff - a.coeffs[4*i+j]
		}
		r[7*i+0] = byte(t[0])
		r[7*i+1] = byte(t[0] >> 8)
		r[7*i+1] |= byte(t[1] << 6)
		r[7*i+2] = byte(t[1] >> 2)
		r[7*i+3] = byte(t[1] >> 10)
		r[7*i+3] |= byte(t[2] << 4)
		r[7*i+4] = byte(t[2] >> 4)
		r[7*i+5] = byte(t[2] >> 12)
		r[7*i+5] |= byte(t[3] << 2)
		r[7*i+6] = byte(t[3] >> 6)
	}
}

func (p *aigisStdParams) polyT0Unpack(a *aigisStdPoly, r []byte) {
	qOff := p.q + uint32(1<<uint(p.d-1))
	if p.d == 13 {
		for i := 0; i < aigisStdN/8; i++ {
			a.coeffs[8*i+0] = uint32(r[13*i+0])
			a.coeffs[8*i+0] |= uint32(r[13*i+1]&0x1F) << 8
			a.coeffs[8*i+1] = uint32(r[13*i+1]) >> 5
			a.coeffs[8*i+1] |= uint32(r[13*i+2]) << 3
			a.coeffs[8*i+1] |= uint32(r[13*i+3]&0x03) << 11
			a.coeffs[8*i+2] = uint32(r[13*i+3]) >> 2
			a.coeffs[8*i+2] |= uint32(r[13*i+4]&0x7F) << 6
			a.coeffs[8*i+3] = uint32(r[13*i+4]) >> 7
			a.coeffs[8*i+3] |= uint32(r[13*i+5]) << 1
			a.coeffs[8*i+3] |= uint32(r[13*i+6]&0x0F) << 9
			a.coeffs[8*i+4] = uint32(r[13*i+6]) >> 4
			a.coeffs[8*i+4] |= uint32(r[13*i+7]) << 4
			a.coeffs[8*i+4] |= uint32(r[13*i+8]&0x01) << 12
			a.coeffs[8*i+5] = uint32(r[13*i+8]) >> 1
			a.coeffs[8*i+5] |= uint32(r[13*i+9]&0x3F) << 7
			a.coeffs[8*i+6] = uint32(r[13*i+9]) >> 6
			a.coeffs[8*i+6] |= uint32(r[13*i+10]) << 2
			a.coeffs[8*i+6] |= uint32(r[13*i+11]&0x07) << 10
			a.coeffs[8*i+7] = uint32(r[13*i+11]) >> 3
			a.coeffs[8*i+7] |= uint32(r[13*i+12]) << 5
			for j := 0; j < 8; j++ {
				a.coeffs[8*i+j] = qOff - a.coeffs[8*i+j]
			}
		}
		return
	}
	for i := 0; i < aigisStdN/4; i++ {
		a.coeffs[4*i+0] = uint32(r[7*i+0])
		a.coeffs[4*i+0] |= uint32(r[7*i+1]&0x3F) << 8
		a.coeffs[4*i+1] = uint32(r[7*i+1]) >> 6
		a.coeffs[4*i+1] |= uint32(r[7*i+2]) << 2
		a.coeffs[4*i+1] |= uint32(r[7*i+3]&0x0F) << 10
		a.coeffs[4*i+2] = uint32(r[7*i+3]) >> 4
		a.coeffs[4*i+2] |= uint32(r[7*i+4]) << 4
		a.coeffs[4*i+2] |= uint32(r[7*i+5]&0x03) << 12
		a.coeffs[4*i+3] = uint32(r[7*i+5]) >> 2
		a.coeffs[4*i+3] |= uint32(r[7*i+6]) << 6
		for j := 0; j < 4; j++ {
			a.coeffs[4*i+j] = qOff - a.coeffs[4*i+j]
		}
	}
}

func (p *aigisStdParams) polyZPack(r []byte, a *aigisStdPoly) {
	g1m1 := p.g1 - 1
	var t [4]uint32
	for i := 0; i < aigisStdN/4; i++ {
		for j := 0; j < 4; j++ {
			t[j] = g1m1 - a.coeffs[4*i+j]
			t[j] += uint32(int32(t[j])>>31) & p.q
		}
		r[9*i+0] = byte(t[0])
		r[9*i+1] = byte(t[0] >> 8)
		r[9*i+2] = byte(t[0] >> 16)
		r[9*i+2] |= byte(t[1] << 2)
		r[9*i+3] = byte(t[1] >> 6)
		r[9*i+4] = byte(t[1] >> 14)
		r[9*i+4] |= byte(t[2] << 4)
		r[9*i+5] = byte(t[2] >> 4)
		r[9*i+6] = byte(t[2] >> 12)
		r[9*i+6] |= byte(t[3] << 6)
		r[9*i+7] = byte(t[3] >> 2)
		r[9*i+8] = byte(t[3] >> 10)
	}
}

func (p *aigisStdParams) polyZUnpack(a *aigisStdPoly, r []byte) {
	g1m1 := p.g1 - 1
	for i := 0; i < aigisStdN/4; i++ {
		a.coeffs[4*i+0] = uint32(r[9*i+0])
		a.coeffs[4*i+0] |= uint32(r[9*i+1]) << 8
		a.coeffs[4*i+0] |= uint32(r[9*i+2]&0x03) << 16
		a.coeffs[4*i+0] = g1m1 - a.coeffs[4*i+0]
		a.coeffs[4*i+0] += uint32(int32(a.coeffs[4*i+0])>>31) & p.q

		a.coeffs[4*i+1] = uint32(r[9*i+2]) >> 2
		a.coeffs[4*i+1] |= uint32(r[9*i+3]) << 6
		a.coeffs[4*i+1] |= uint32(r[9*i+4]&0x0F) << 14
		a.coeffs[4*i+1] = g1m1 - a.coeffs[4*i+1]
		a.coeffs[4*i+1] += uint32(int32(a.coeffs[4*i+1])>>31) & p.q

		a.coeffs[4*i+2] = uint32(r[9*i+4]) >> 4
		a.coeffs[4*i+2] |= uint32(r[9*i+5]) << 4
		a.coeffs[4*i+2] |= uint32(r[9*i+6]&0x3F) << 12
		a.coeffs[4*i+2] = g1m1 - a.coeffs[4*i+2]
		a.coeffs[4*i+2] += uint32(int32(a.coeffs[4*i+2])>>31) & p.q

		a.coeffs[4*i+3] = uint32(r[9*i+6]) >> 6
		a.coeffs[4*i+3] |= uint32(r[9*i+7]) << 2
		a.coeffs[4*i+3] |= uint32(r[9*i+8]) << 10
		a.coeffs[4*i+3] = g1m1 - a.coeffs[4*i+3]
		a.coeffs[4*i+3] += uint32(int32(a.coeffs[4*i+3])>>31) & p.q
	}
}

func (p *aigisStdParams) polyW1Pack(r []byte, a *aigisStdPoly) {
	for i := 0; i < aigisStdN/8; i++ {
		c0 := a.coeffs[8*i+0]
		c1 := a.coeffs[8*i+1]
		c2 := a.coeffs[8*i+2]
		c3 := a.coeffs[8*i+3]
		c4 := a.coeffs[8*i+4]
		c5 := a.coeffs[8*i+5]
		c6 := a.coeffs[8*i+6]
		c7 := a.coeffs[8*i+7]
		r[3*i+0] = byte(c0 | (c1 << 3) | (c2 << 6))
		r[3*i+1] = byte((c2 >> 2) | (c3 << 1) | (c4 << 4) | (c5 << 7))
		r[3*i+2] = byte((c5 >> 1) | (c6 << 2) | (c7 << 5))
	}
}

// ─────────────────────────────────────────────────────────────
// 多项式向量 (polyvec.c)
// ─────────────────────────────────────────────────────────────

type aigisStdVecL struct {
	vec [6]aigisStdPoly // L ≤ 5
}

type aigisStdVecK struct {
	vec [6]aigisStdPoly // K ≤ 6
}

func (p *aigisStdParams) vecLFreeze2q(v *aigisStdVecL) {
	for i := 0; i < p.l; i++ {
		p.polyFreeze2q(&v.vec[i])
	}
}

func (p *aigisStdParams) vecLFreeze4q(v *aigisStdVecL) {
	for i := 0; i < p.l; i++ {
		p.polyFreeze4q(&v.vec[i])
	}
}

func (p *aigisStdParams) vecLAdd(w, u, v *aigisStdVecL) {
	for i := 0; i < p.l; i++ {
		p.polyAdd(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func (p *aigisStdParams) vecLNTT(v *aigisStdVecL) {
	for i := 0; i < p.l; i++ {
		p.polyNTT(&v.vec[i])
	}
}

// vecLPointwiseAcc: w = Σ u_i ⊙ v_i，最后做 Barrett 约减
func (p *aigisStdParams) vecLPointwiseAcc(w *aigisStdPoly, u *aigisStdVecL, v *aigisStdVecL) {
	var t aigisStdPoly
	p.polyPointwiseInvMont(w, &u.vec[0], &v.vec[0])
	for i := 1; i < p.l; i++ {
		p.polyPointwiseInvMont(&t, &u.vec[i], &v.vec[i])
		p.polyAdd(w, w, &t)
	}
	for i := 0; i < aigisStdN; i++ {
		w.coeffs[i] = p.barratReduce(w.coeffs[i])
	}
}

func (p *aigisStdParams) vecLChkNORM(v *aigisStdVecL, bound uint32) bool {
	for i := 0; i < p.l; i++ {
		if p.polyChkNORM(&v.vec[i], bound) {
			return true
		}
	}
	return false
}

func (p *aigisStdParams) vecKFreeze2q(v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		p.polyFreeze2q(&v.vec[i])
	}
}

func (p *aigisStdParams) vecKFreeze4q(v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		p.polyFreeze4q(&v.vec[i])
	}
}

func (p *aigisStdParams) vecKAdd(w, u, v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		p.polyAdd(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func (p *aigisStdParams) vecKSub(w, u, v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		p.polySub(&w.vec[i], &u.vec[i], &v.vec[i])
	}
}

func (p *aigisStdParams) vecKNeg(v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		p.polyNeg(&v.vec[i])
	}
}

func (p *aigisStdParams) vecKShiftl(v *aigisStdVecK, k uint) {
	for i := 0; i < p.k; i++ {
		p.polyShiftl(&v.vec[i], k)
	}
}

func (p *aigisStdParams) vecKNTT(v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		p.polyNTT(&v.vec[i])
	}
}

func (p *aigisStdParams) vecKInvNTTMont(v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		p.polyInvNTTMont(&v.vec[i])
	}
}

func (p *aigisStdParams) vecKChkNORM(v *aigisStdVecK, bound uint32) bool {
	for i := 0; i < p.k; i++ {
		if p.polyChkNORM(&v.vec[i], bound) {
			return true
		}
	}
	return false
}

func (p *aigisStdParams) vecKPower2round(v1, v0, v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		for j := 0; j < aigisStdN; j++ {
			v1.vec[i].coeffs[j], v0.vec[i].coeffs[j] = p.power2round(v.vec[i].coeffs[j])
		}
	}
}

func (p *aigisStdParams) vecKDecompose(v1, v0, v *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		for j := 0; j < aigisStdN; j++ {
			v1.vec[i].coeffs[j], v0.vec[i].coeffs[j] = p.decompose(v.vec[i].coeffs[j])
		}
	}
}

func (p *aigisStdParams) vecKMakeHint(h, u, v *aigisStdVecK) int {
	s := 0
	for i := 0; i < p.k; i++ {
		for j := 0; j < aigisStdN; j++ {
			hv := p.makeHint(u.vec[i].coeffs[j], v.vec[i].coeffs[j])
			h.vec[i].coeffs[j] = hv
			s += int(hv)
		}
	}
	return s
}

func (p *aigisStdParams) vecKUseHint(w, u, h *aigisStdVecK) {
	for i := 0; i < p.k; i++ {
		for j := 0; j < aigisStdN; j++ {
			w.vec[i].coeffs[j] = p.useHint(u.vec[i].coeffs[j], h.vec[i].coeffs[j])
		}
	}
}

// ─────────────────────────────────────────────────────────────
// 打包 (packing.c)
// ─────────────────────────────────────────────────────────────

func (p *aigisStdParams) packPK(pk []byte, rho []byte, t1 *aigisStdVecK) {
	copy(pk, rho)
	off := 32
	for i := 0; i < p.k; i++ {
		p.polyT1Pack(pk[off+i*p.polt1Size:], &t1.vec[i])
	}
}

func (p *aigisStdParams) unpackPK(rho []byte, t1 *aigisStdVecK, pk []byte) {
	copy(rho, pk)
	off := 32
	for i := 0; i < p.k; i++ {
		p.polyT1Unpack(&t1.vec[i], pk[off+i*p.polt1Size:])
	}
}

func (p *aigisStdParams) packSK(sk []byte, buf []byte, s1 *aigisStdVecL, s2, t0 *aigisStdVecK) {
	off := 0
	copy(sk, buf)
	off += 112 // 2*32 + 48
	for i := 0; i < p.l; i++ {
		p.polyEta1Pack(sk[off+i*p.poleta1Size:], &s1.vec[i])
	}
	off += p.l * p.poleta1Size
	for i := 0; i < p.k; i++ {
		p.polyEta2Pack(sk[off+i*p.poleta2Size:], &s2.vec[i])
	}
	off += p.k * p.poleta2Size
	for i := 0; i < p.k; i++ {
		p.polyT0Pack(sk[off+i*p.polt0Size:], &t0.vec[i])
	}
}

func (p *aigisStdParams) unpackSK(buf []byte, s1 *aigisStdVecL, s2, t0 *aigisStdVecK, sk []byte) {
	off := 0
	copy(buf, sk)
	off += 112
	for i := 0; i < p.l; i++ {
		p.polyEta1Unpack(&s1.vec[i], sk[off+i*p.poleta1Size:])
	}
	off += p.l * p.poleta1Size
	for i := 0; i < p.k; i++ {
		p.polyEta2Unpack(&s2.vec[i], sk[off+i*p.poleta2Size:])
	}
	off += p.k * p.poleta2Size
	for i := 0; i < p.k; i++ {
		p.polyT0Unpack(&t0.vec[i], sk[off+i*p.polt0Size:])
	}
}

func (p *aigisStdParams) packSig(sig []byte, z *aigisStdVecL, h *aigisStdVecK, c *aigisStdPoly) {
	off := 0
	for i := 0; i < p.l; i++ {
		p.polyZPack(sig[off+i*p.polzSize:], &z.vec[i])
	}
	off += p.l * p.polzSize

	// h: 位置列表
	k := 0
	for i := 0; i < p.k; i++ {
		for j := 0; j < aigisStdN; j++ {
			if h.vec[i].coeffs[j] == 1 {
				sig[off+k] = byte(j)
				k++
			}
		}
		sig[off+p.omega+i] = byte(k)
	}
	for k < p.omega {
		sig[off+k] = 0
		k++
	}
	off += p.omega + p.k

	// c: 32 字节位图 + 8 字节符号
	var signs uint64
	mask := uint64(1)
	for i := 0; i < aigisStdN/8; i++ {
		sig[off+i] = 0
		for j := 0; j < 8; j++ {
			if c.coeffs[8*i+j] != 0 {
				sig[off+i] |= 1 << uint(j)
				if c.coeffs[8*i+j] == p.q-1 {
					signs |= mask
				}
				mask <<= 1
			}
		}
	}
	off += aigisStdN / 8
	binary.LittleEndian.PutUint64(sig[off:], signs)
}

func (p *aigisStdParams) unpackSig(z *aigisStdVecL, h *aigisStdVecK, c *aigisStdPoly, sig []byte) bool {
	off := 0
	for i := 0; i < p.l; i++ {
		p.polyZUnpack(&z.vec[i], sig[off+i*p.polzSize:])
	}
	off += p.l * p.polzSize

	// h
	k := 0
	for i := 0; i < p.k; i++ {
		for j := 0; j < aigisStdN; j++ {
			h.vec[i].coeffs[j] = 0
		}
		ck := int(sig[off+p.omega+i])
		if ck < k || ck > p.omega {
			return false
		}
		for j := k; j < ck; j++ {
			if j > k && sig[off+j] <= sig[off+j-1] {
				return false
			}
			h.vec[i].coeffs[sig[off+j]] = 1
		}
		k = ck
	}
	for j := k; j < p.omega; j++ {
		if sig[off+j] != 0 {
			return false
		}
	}
	off += p.omega + p.k

	// c
	for i := 0; i < aigisStdN; i++ {
		c.coeffs[i] = 0
	}
	signs := binary.LittleEndian.Uint64(sig[off+aigisStdN/8:])
	mask := uint64(1)
	for i := 0; i < aigisStdN/8; i++ {
		for j := 0; j < 8; j++ {
			if (sig[off+i]>>uint(j))&0x01 != 0 {
				if signs&mask != 0 {
					c.coeffs[8*i+j] = p.q - 1
				} else {
					c.coeffs[8*i+j] = 1
				}
				mask <<= 1
			}
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────
// expand_mat / challenge (sign.c)
// ─────────────────────────────────────────────────────────────

// expandMat: 从 rho 展开公钥矩阵 A
func (p *aigisStdParams) expandMat(mat []aigisStdVecL, rho []byte, mode aigisHashMode) {
	inbuf := make([]byte, 34)
	copy(inbuf, rho)
	for i := 0; i < p.k; i++ {
		for j := 0; j < p.l; j++ {
			ctr := 0
			pos := 0
			inbuf[32] = byte(i + (j << 4))
			var outbuf []byte
			if p.qbits == 21 {
				outbuf = make([]byte, 6*168)
			} else {
				outbuf = make([]byte, 7*168)
			}
			if mode == aigisHashSHAKE {
				h := sha3.NewShake128()
				h.Write(inbuf[:33])
				h.Read(outbuf)
			} else {
				inbuf[33] = 0
				sm3Extended(outbuf[:6*168], inbuf[:34])
			}
			if p.qbits == 21 {
				for ctr < aigisStdN {
					val := uint32(outbuf[pos])
					val |= uint32(outbuf[pos+1]) << 8
					val |= uint32(outbuf[pos+2]) << 16
					pos += 3
					val &= 0x1FFFFF
					if val < p.q {
						mat[i].vec[j].coeffs[ctr] = val
						ctr++
					}
				}
			} else {
				for ctr < 225 {
					val := uint32(outbuf[pos])
					val |= uint32(outbuf[pos+1]) << 8
					val |= uint32(outbuf[pos+2]) << 16
					pos += 3
					val &= 0x3FFFFF
					if val < p.q {
						mat[i].vec[j].coeffs[ctr] = val
						ctr++
					}
				}
				// 剩余字节不足时补第 7 块
				// （SHAKE 模式 outbuf 已一次性读出 7 块，无需处理；
				//   SM3 模式第 7 块需用尾部字节=1 重新扩展）
				if 6*168-pos < 258 && mode != aigisHashSHAKE {
					inbuf[33] = 1
					sm3Extended(outbuf[6*168:7*168], inbuf[:34])
				}
				for ctr < aigisStdN {
					val := uint32(outbuf[pos])
					val |= uint32(outbuf[pos+1]) << 8
					val |= uint32(outbuf[pos+2]) << 16
					pos += 3
					val &= 0x3FFFFF
					if val < p.q {
						mat[i].vec[j].coeffs[ctr] = val
						ctr++
					}
				}
			}
		}
	}
}

// challenge: 生成挑战 c（固定 60 个 ±1）
func (p *aigisStdParams) challenge(c *aigisStdPoly, mu []byte, w1 *aigisStdVecK, mode aigisHashMode) {
	inbuf := make([]byte, 48+p.k*p.polw1Size)
	copy(inbuf, mu)
	for i := 0; i < p.k; i++ {
		p.polyW1Pack(inbuf[48+i*p.polw1Size:], &w1.vec[i])
	}

	outbuf := make([]byte, 136)
	var readBlock func()
	blockIdx := 0
	if mode == aigisHashSHAKE {
		h := sha3.NewShake256()
		h.Write(inbuf)
		readBlock = func() {
			h.Read(outbuf)
		}
	} else {
		inbufExt := make([]byte, len(inbuf)+1)
		copy(inbufExt, inbuf)
		readBlock = func() {
			inbufExt[len(inbuf)] = byte(blockIdx)
			blockIdx++
			sm3Extended(outbuf, inbufExt)
		}
	}
	readBlock()

	signs := uint64(0)
	for i := 0; i < 8; i++ {
		signs |= uint64(outbuf[i]) << (8 * uint(i))
	}
	pos := 8
	mask := uint64(1)
	for i := 0; i < aigisStdN; i++ {
		c.coeffs[i] = 0
	}
	for i := 196; i < 256; i++ {
		var b int
		for {
			if pos >= 136 {
				readBlock()
				pos = 0
			}
			b = int(outbuf[pos])
			pos++
			if b <= i {
				break
			}
		}
		c.coeffs[i] = c.coeffs[b]
		if signs&mask != 0 {
			c.coeffs[b] = p.q - 1
		} else {
			c.coeffs[b] = 1
		}
		mask <<= 1
	}
}

// ─────────────────────────────────────────────────────────────
// 密钥生成 / 签名 / 验签 (sign.c)
// ─────────────────────────────────────────────────────────────

// keypairInternal: 用 coins 确定性生成 (pk, sk)
func (p *aigisStdParams) keypairInternal(coins []byte, mode aigisHashMode) (pk, sk []byte) {
	pk = make([]byte, p.pkSize)
	sk = make([]byte, p.skSize)
	buf := make([]byte, 3*32+48) // r | rho | key | tr
	if mode == aigisHashSHAKE {
		sha3.ShakeSum256(buf[:3*32], coins[:32])
	} else {
		sm3Extended(buf[:3*32], coins[:32])
	}

	mat := p.newMat()
	p.expandMat(mat, buf[32:64], mode)

	var nonce byte
	var s1 aigisStdVecL
	var s2 aigisStdVecK
	for i := 0; i < p.l; i++ {
		p.polyUniformEta1(&s1.vec[i], buf[:32], nonce, mode)
		nonce++
	}
	for i := 0; i < p.k; i++ {
		p.polyUniformEta2(&s2.vec[i], buf[:32], nonce, mode)
		nonce++
	}

	s1hat := s1
	p.vecLNTT(&s1hat)
	var t, t1, t0 aigisStdVecK
	for i := 0; i < p.k; i++ {
		p.vecLPointwiseAcc(&t.vec[i], &mat[i], &s1hat)
		p.polyInvNTTMont(&t.vec[i])
	}
	p.vecKAdd(&t, &t, &s2)
	p.vecKFreeze4q(&t)
	p.vecKPower2round(&t1, &t0, &t)

	p.packPK(pk, buf[32:64], &t1)
	p.hash(buf[96:144], pk, mode)
	p.packSK(sk, buf[32:], &s1, &s2, &t0)
	return pk, sk
}

// newMat: 分配 K×L 矩阵（行类型为 polyvecl）
func (p *aigisStdParams) newMat() []aigisStdVecL {
	return make([]aigisStdVecL, p.k)
}

// signInternal: 用 sk 对消息 m 签名
func (p *aigisStdParams) signInternal(sk, m []byte, mode aigisHashMode) ([]byte, error) {
	if len(sk) != p.skSize {
		return nil, errors.New("私钥长度错误")
	}
	sig := make([]byte, p.sigSize)
	buf := make([]byte, 112+len(m))

	var s1 aigisStdVecL
	var s2, t0 aigisStdVecK
	p.unpackSK(buf, &s1, &s2, &t0, sk)
	copy(buf[112:], m)

	// mu = CRH(key || tr || m) = CRH(buf[64:112] || m)
	p.hash(buf[64:112], buf[64:112+len(m)], mode)

	mat := p.newMat()
	p.expandMat(mat, buf[:32], mode)

	p.vecLNTT(&s1)
	p.vecKNTT(&s2)
	p.vecKNTT(&t0)

	var nonce uint16
	var c, chat aigisStdPoly
	var y, yhat, z aigisStdVecL
	var w, w1, wcs2, wcs20, ct0, tmp, h aigisStdVecK

rej:
	for i := 0; i < p.l; i++ {
		p.polyUniformGamma1m1(&y.vec[i], buf[32:112], nonce, mode)
		nonce++
	}
	yhat = y
	p.vecLNTT(&yhat)
	for i := 0; i < p.k; i++ {
		p.vecLPointwiseAcc(&w.vec[i], &mat[i], &yhat)
		p.polyInvNTTMont(&w.vec[i])
	}
	p.vecKFreeze2q(&w)
	p.vecKDecompose(&w1, &tmp, &w)
	p.challenge(&c, buf[64:112], &w1, mode)

	chat = c
	p.polyNTT(&chat)
	for i := 0; i < p.l; i++ {
		p.polyPointwiseInvMont(&z.vec[i], &chat, &s1.vec[i])
		p.polyInvNTTMont(&z.vec[i])
	}
	p.vecLAdd(&z, &z, &y)
	p.vecLFreeze4q(&z)
	if p.vecLChkNORM(&z, p.g1-uint32(p.beta1)) {
		goto rej
	}

	for i := 0; i < p.k; i++ {
		p.polyPointwiseInvMont(&wcs2.vec[i], &chat, &s2.vec[i])
		p.polyInvNTTMont(&wcs2.vec[i])
	}
	p.vecKSub(&wcs2, &w, &wcs2)
	p.vecKFreeze4q(&wcs2)
	p.vecKDecompose(&tmp, &wcs20, &wcs2)
	p.vecKFreeze2q(&wcs20)
	if p.vecKChkNORM(&wcs20, p.g2-uint32(p.beta2)) {
		goto rej
	}

	for i := 0; i < p.k; i++ {
		for j := 0; j < aigisStdN; j++ {
			if tmp.vec[i].coeffs[j] != w1.vec[i].coeffs[j] {
				goto rej
			}
		}
	}

	for i := 0; i < p.k; i++ {
		p.polyPointwiseInvMont(&ct0.vec[i], &chat, &t0.vec[i])
		p.polyInvNTTMont(&ct0.vec[i])
	}
	p.vecKFreeze2q(&ct0)
	if p.vecKChkNORM(&ct0, p.g2) {
		goto rej
	}

	p.vecKAdd(&tmp, &wcs2, &ct0)
	p.vecKNeg(&ct0)
	p.vecKFreeze2q(&tmp)
	n := p.vecKMakeHint(&h, &tmp, &ct0)
	if n > p.omega {
		goto rej
	}

	p.packSig(sig, &z, &h, &c)
	return sig, nil
}

// verifyInternal: 验签
func (p *aigisStdParams) verifyInternal(sig, m, pk []byte, mode aigisHashMode) bool {
	if len(sig) != p.sigSize || len(pk) != p.pkSize {
		return false
	}
	var rho [32]byte
	var t1, w1, h, tmp1, tmp2 aigisStdVecK
	var z aigisStdVecL
	var c, chat, cp aigisStdPoly

	p.unpackPK(rho[:], &t1, pk)
	if !p.unpackSig(&z, &h, &c, sig) {
		return false
	}
	if p.vecLChkNORM(&z, p.g1-uint32(p.beta1)) {
		return false
	}

	buf := make([]byte, 48+len(m))
	copy(buf[48:], m)
	// mu = CRH(CRH(pk) || m)
	p.hash(buf[:48], pk, mode)
	p.hash(buf[:48], buf[:48+len(m)], mode)

	mat := p.newMat()
	p.expandMat(mat, rho[:], mode)

	p.vecLNTT(&z)
	for i := 0; i < p.k; i++ {
		p.vecLPointwiseAcc(&tmp1.vec[i], &mat[i], &z)
	}

	chat = c
	p.polyNTT(&chat)
	p.vecKShiftl(&t1, uint(p.d))
	p.vecKNTT(&t1)
	for i := 0; i < p.k; i++ {
		p.polyPointwiseInvMont(&tmp2.vec[i], &chat, &t1.vec[i])
	}
	p.vecKSub(&tmp1, &tmp1, &tmp2)
	p.vecKInvNTTMont(&tmp1)
	p.vecKFreeze2q(&tmp1)
	p.vecKUseHint(&w1, &tmp1, &h)

	p.challenge(&cp, buf[:48], &w1, mode)
	for i := 0; i < aigisStdN; i++ {
		if c.coeffs[i] != cp.coeffs[i] {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────
// 公开 API (与现有 pqc.go / app.go 接口对齐)
// ─────────────────────────────────────────────────────────────

// parseAigisParamSet 解析参数集字符串，返回参数与哈希模式。
// 合法取值：AIGIS-sig-1/2/3（可带 -SM3 / -SHAKE 后缀，默认 SM3）。
func parseAigisParamSet(paramSet string) (*aigisStdParams, aigisHashMode, bool) {
	s := paramSet
	mode := aigisHashSM3
	up := strings.ToUpper(s)
	if strings.HasSuffix(up, "-SHAKE") {
		mode = aigisHashSHAKE
		up = strings.TrimSuffix(up, "-SHAKE")
	} else if strings.HasSuffix(up, "-SM3") {
		up = strings.TrimSuffix(up, "-SM3")
	}
	up = strings.ReplaceAll(up, "-", "")
	up = strings.ReplaceAll(up, "_", "")
	var p *aigisStdParams
	switch up {
	case "AIGISSIG1", "AIGIS1", "AIGISSIGI", "1":
		p = &aigisStdParamsList[0]
	case "AIGISSIG2", "AIGIS2", "AIGISSIGII", "2":
		p = &aigisStdParamsList[1]
	case "AIGISSIG3", "AIGIS3", "AIGISSIGIII", "3":
		p = &aigisStdParamsList[2]
	default:
		return nil, mode, false
	}
	return p, mode, true
}

func AigisKeyGen(paramSet string) PQCKeyResult {
	p, mode, ok := parseAigisParamSet(paramSet)
	if !ok {
		return PQCKeyResult{Error: "不支持的 AIGIS-sig 参数集: " + paramSet, ParamSet: paramSet}
	}
	coins := make([]byte, 32)
	if _, err := rand.Read(coins); err != nil {
		return PQCKeyResult{Error: "AIGIS 密钥生成失败: " + err.Error(), ParamSet: paramSet}
	}
	pk, sk := p.keypairInternal(coins, mode)
	return PQCKeyResult{
		Success:    true,
		PublicKey:  hexUpper(pk),
		PrivateKey: hexUpper(sk),
		ParamSet:   p.name + "-" + mode.String(),
	}
}

func AigisSign(req SLHDSARequest) symmetric.CryptoResult {
	p, mode, ok := parseAigisParamSet(req.ParamSet)
	if !ok {
		return symmetric.CryptoResult{Error: "不支持的 AIGIS-sig 参数集: " + req.ParamSet}
	}
	skBytes, err := hex.DecodeString(req.PrivateKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效私钥(hex): " + err.Error()}
	}
	msgBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效数据(hex): " + err.Error()}
	}
	sig, err := p.signInternal(skBytes, msgBytes, mode)
	if err != nil {
		return symmetric.CryptoResult{Error: err.Error()}
	}
	return symmetric.CryptoResult{Success: true, Data: hexUpper(sig)}
}

func AigisVerify(req SLHDSAVerifyRequest) symmetric.CryptoResult {
	p, mode, ok := parseAigisParamSet(req.ParamSet)
	if !ok {
		return symmetric.CryptoResult{Error: "不支持的 AIGIS-sig 参数集: " + req.ParamSet}
	}
	pkBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效公钥(hex): " + err.Error()}
	}
	msgBytes, err := hex.DecodeString(req.Data)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效数据(hex): " + err.Error()}
	}
	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return symmetric.CryptoResult{Error: "无效签名(hex): " + err.Error()}
	}
	if p.verifyInternal(sigBytes, msgBytes, pkBytes, mode) {
		return symmetric.CryptoResult{Success: true, Data: "true"}
	}
	return symmetric.CryptoResult{Success: false, Data: "false", Error: "验签失败"}
}

// Format 报告参数与密钥尺寸（供前端展示）。
func (p *aigisStdParams) String() string {
	return fmt.Sprintf("%s: q=%d K=%d L=%d D=%d | pk=%dB sk=%dB sig=%dB",
		p.name, p.q, p.k, p.l, p.d, p.pkSize, p.skSize, p.sigSize)
}
