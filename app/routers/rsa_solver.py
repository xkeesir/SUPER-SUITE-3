import re
import itertools
from typing import List, Dict, Any, Optional, Union

import gmpy2
<<<<<<< HEAD
from pydantic import BaseModel
=======
>>>>>>> 3e068d5fcc9577429dffd86e6c8086867b0817c7
from Crypto.Util.number import long_to_bytes
from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/rsa", tags=["rsa"])

<<<<<<< HEAD
# 防止排列组合爆炸：permutations(N,5) 在 N>20 时会膨胀到千万级
MAX_NUMBERS = 20

=======
>>>>>>> 3e068d5fcc9577429dffd86e6c8086867b0817c7

# ==========================================
# 辅助工具
# ==========================================
def is_readable(byte_data: Optional[bytes]) -> bool:
    if not byte_data:
        return False
    try:
        text = byte_data.decode("utf-8")
        if "flag{" in text.lower() or "ctf{" in text.lower():
            return True
        printable = sum(1 for c in text if 32 <= ord(c) <= 126 or ord(c) in (9, 10, 13))
        if len(text) > 5 and printable / len(text) > 0.9:
            return True
    except Exception:
        pass
    return False


def exgcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = exgcd(b % a, a)
    return (g, x - (b // a) * y, y)


def crt(remainders, moduli):
    total = 0
    prod = 1
    for n in moduli:
        prod *= n
    for a_i, n_i in zip(remainders, moduli):
        p = prod // n_i
        total += a_i * int(gmpy2.invert(p, n_i)) * p
    return total % prod


def rational_to_contfrac(x, y):
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients


def convergents_from_contfrac(frac):
    convs = []
    for i in range(len(frac)):
        if i == 0:
            ni, di = frac[0], 1
        elif i == 1:
            ni, di = frac[0] * frac[1] + 1, frac[1]
        else:
            ni = frac[i] * convs[i - 1][0] + convs[i - 2][0]
            di = frac[i] * convs[i - 1][1] + convs[i - 2][1]
        convs.append((ni, di))
    return convs


# ==========================================
# 攻击模式
# ==========================================
def attack_known_pq(p, q, e, c):
    n = p * q
    if c >= n or e >= n:
        return None
    phi = (p - 1) * (q - 1)
    try:
        d = int(gmpy2.invert(e, phi))
        m = pow(c, d, n)
        return long_to_bytes(int(m))
    except Exception:
        return None


def attack_small_e(n, e, c):
    if e > 100:
        return None
    gmpy2.get_context().precision = 4096
    m, is_exact = gmpy2.iroot(c, e)
    if is_exact:
        return long_to_bytes(int(m))
    return None


def attack_fermat(n, e, c):
    a = gmpy2.isqrt(n)
    b2 = gmpy2.square(a) - n
    limit = 10000
    count = 0
    while not gmpy2.is_square(b2) and count < limit:
        a += 1
        b2 = gmpy2.square(a) - n
        count += 1
    if gmpy2.is_square(b2):
        p = a - gmpy2.isqrt(b2)
        q = n // p
        if p * q == n:
            return attack_known_pq(p, q, e, c)
    return None


def attack_wiener(n, e, c):
    if e <= 10000:
        return None
    frac = rational_to_contfrac(e, n)
    conv = convergents_from_contfrac(frac)
    for k, d in conv:
        if k == 0 or d % 2 == 0 or e * d % k != 1:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        delta = b * b - 4 * n
        if delta >= 0 and gmpy2.is_square(delta):
            m = pow(c, d, n)
            return long_to_bytes(int(m))
    return None


def attack_common_modulus(n, e1, e2, c1, c2):
    g, s1, s2 = exgcd(e1, e2)
    if g != 1:
        return None
    try:
        if s1 < 0:
            c1 = int(gmpy2.invert(c1, n))
            s1 = -s1
        if s2 < 0:
            c2 = int(gmpy2.invert(c2, n))
            s2 = -s2
        m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
        return long_to_bytes(int(m))
    except Exception:
        return None


def attack_hastad_broadcast(array):
    potential_es = [x for x in array if 3 <= x <= 11 and x % 2 != 0]
    unreadable = []
    
    for e in potential_es:
        others = [x for x in array if x != e]
        valid_pairs = [(n, c) for n, c in itertools.permutations(others, 2) if n > c and n % 2 != 0]
        if len(valid_pairs) < e:
            continue

        for combo in itertools.combinations(valid_pairs, e):
            used_nums = set()
            for n, c in combo:
                used_nums.add(n)
                used_nums.add(c)
            if len(used_nums) == 2 * e:
                ns = [p[0] for p in combo]
                cs = [p[1] for p in combo]

                coprime = True
                for i in range(len(ns)):
                    for j in range(i + 1, len(ns)):
                        if gmpy2.gcd(ns[i], ns[j]) != 1:
                            coprime = False
                            break
                    if not coprime:
                        break

                if coprime:
                    C = crt(cs, ns)
                    gmpy2.get_context().precision = 4096
                    m, is_exact = gmpy2.iroot(C, e)
                    if is_exact:
                        res = long_to_bytes(int(m))
                        if is_readable(res):
                            return True, (res, e, ns)
                        else:
                            unreadable.append((res, e, ns))
                            
    if unreadable:
        return False, unreadable
    return None, None


def attack_shared_prime(array):
    potential_ns = [x for x in array if x > 1000 and x % 2 != 0]
    unreadable = []

    for n1, n2 in itertools.combinations(potential_ns, 2):
        if n1 == n2:
            continue
        g = gmpy2.gcd(n1, n2)

        if 1 < g < n1:
            p = int(g)
            targets = [
                (n1, p, n1 // p),
                (n2, p, n2 // p),
            ]

            for n_target, p_target, q_target in targets:
                others = [x for x in array if x != n_target]
                for e, c in itertools.permutations(others, 2):
                    if e < 3 or e % 2 == 0 or c >= n_target:
                        continue
                    res = attack_known_pq(p_target, q_target, e, c)
                    if res is not None:
                        if is_readable(res):
                            return True, (res, n_target, p_target, q_target)
                        else:
                            unreadable.append((res, n_target, p_target, q_target))
                            
    if unreadable:
        return False, unreadable
    return None, None


# ==========================================
# 调度核心
# ==========================================
def _short(val: Union[int, str], head: int = 18) -> str:
    s = str(val)
    return s if len(s) <= head + 5 else f"{s[:head]}...({len(s)} chars)"


def all_in_one_rsa_solver(array: List[int]) -> Dict[str, Any]:
    logs: List[Dict[str, str]] = []
    unreadable_results: List[Dict[str, Any]] = []

    def log(msg: str, type_: str = "info"):
        logs.append({"msg": msg, "type": type_})

    def add_unreadable(mode: str, res_bytes: bytes, params: dict):
        hex_str = res_bytes.hex()
        # 排重过滤：相同的变量排列组合可能会得出相同的 hex，防止输出爆炸
        if not any(x['hex'] == hex_str for x in unreadable_results):
            unreadable_results.append({
                "mode": mode,
                "hex": hex_str,
                "params": params
            })
            log(f"[?] 发现潜在结果 ({mode})，数据不可读，提取 Hex: {_short(hex_str, 32)}", "info")

    array = list(set(array))
    log(f"[*] 收到 {len(array)} 个唯一参数，开始全自动降维打击...", "system")

    # 阶段 1：3 变量
    log("[>] 阶段 1/5: 扫描 3 变量组合 (基础/小e/Fermat/Wiener)...", "cmd")
    for n, e, c in itertools.permutations(array, 3):
        if n <= c or n <= e or n % 2 == 0 or e < 3 or e % 2 == 0:
            continue
        attacks = [
            ("小指数攻击", attack_small_e),
            ("费马分解", attack_fermat),
            ("Wiener攻击", attack_wiener),
        ]
        for attack_name, attack_func in attacks:
            res = attack_func(n, e, c)
            if res is not None:
                if is_readable(res):
                    log(f"[+] 成功！命中模式: {attack_name}", "success")
                    return {
                        "status": "success",
                        "mode": attack_name,
                        "flag": res.decode("utf-8", errors="replace"),
                        "params": {"n": str(n), "e": str(e), "c": str(c)},
                        "logs": logs,
                    }
                else:
                    add_unreadable(attack_name, res, {"n": str(n), "e": str(e), "c": str(c)})

    # 阶段 2：4 变量已知 p,q
    log("[>] 阶段 2/5: 扫描 4 变量组合 (已知 p, q)...", "cmd")
    if len(array) >= 4:
        for p, q, e, c in itertools.permutations(array, 4):
            if p % 2 == 0 or q % 2 == 0 or p == 1 or q == 1 or e % 2 == 0 or e < 3:
                continue
            res = attack_known_pq(p, q, e, c)
            if res is not None:
                if is_readable(res):
                    log("[+] 成功！命中模式: 已知 p, q 直接解密", "success")
                    return {
                        "status": "success",
                        "mode": "已知 p, q 直接解密",
                        "flag": res.decode("utf-8", errors="replace"),
                        "params": {"p": str(p), "q": str(q), "e": str(e), "c": str(c)},
                        "logs": logs,
                    }
                else:
                    add_unreadable("已知 p, q 直接解密", res, {"p": str(p), "q": str(q), "e": str(e), "c": str(c)})

    # 阶段 3：共享素因子
    log("[>] 阶段 3/5: 扫描多参数漏洞 (共享素因子攻击)...", "cmd")
    is_read_shared, shared_data = attack_shared_prime(array)
    if is_read_shared:
        m_bytes, used_n, p, q = shared_data
        log("[+] 成功！命中模式: 共享素因子攻击 (Shared Prime Factor)", "success")
        log(f"[+] 参数推演: 共享素数 p={_short(p)}, 分解 n={_short(used_n)}", "info")
        return {
            "status": "success",
            "mode": "共享素因子攻击 (Shared Prime Factor)",
            "flag": m_bytes.decode("utf-8", errors="replace"),
            "params": {"n": str(used_n), "p": str(p), "q": str(q)},
            "logs": logs,
        }
    elif shared_data:
        for m_bytes, used_n, p, q in shared_data:
            add_unreadable("共享素因子攻击 (Shared Prime Factor)", m_bytes, {"n": str(used_n), "p": str(p), "q": str(q)})

    # 阶段 4：5 变量共模
    log("[>] 阶段 4/5: 扫描 5 变量组合 (共模攻击)...", "cmd")
    if len(array) >= 5:
        for n, e1, e2, c1, c2 in itertools.permutations(array, 5):
            if (n <= c1 or n <= c2 or n <= e1 or n <= e2
                    or n % 2 == 0 or e1 == e2 or c1 == c2):
                continue
            res = attack_common_modulus(n, e1, e2, c1, c2)
            if res is not None:
                if is_readable(res):
                    log("[+] 成功！命中模式: 共模攻击 (Common Modulus)", "success")
                    return {
                        "status": "success",
                        "mode": "共模攻击 (Common Modulus)",
                        "flag": res.decode("utf-8", errors="replace"),
                        "params": {
                            "n": str(n),
                            "e1": str(e1), "e2": str(e2),
                            "c1": str(c1), "c2": str(c2),
                        },
                        "logs": logs,
                    }
                else:
                    add_unreadable("共模攻击 (Common Modulus)", res, {
                        "n": str(n), "e1": str(e1), "e2": str(e2),
                        "c1": str(c1), "c2": str(c2)
                    })

    # 阶段 5：Hastad 广播
    log("[>] 阶段 5/5: 扫描复杂网络组合 (Hastad 广播攻击)...", "cmd")
    if len(array) >= 7:
        is_read_hastad, hastad_data = attack_hastad_broadcast(array)
        if is_read_hastad:
            m_bytes, used_e, used_ns = hastad_data
            log("[+] 成功！命中模式: Hastad 广播攻击 (CRT)", "success")
            log(f"[+] 参数推演: 共同 e={used_e}, {len(used_ns)} 组 (n,c) 互质对", "info")
            return {
                "status": "success",
                "mode": "Hastad 广播攻击 (CRT)",
                "flag": m_bytes.decode("utf-8", errors="replace"),
                "params": {"e": str(used_e), "ns": [str(x) for x in used_ns]},
                "logs": logs,
            }
        elif hastad_data:
            for m_bytes, used_e, used_ns in hastad_data:
                add_unreadable("Hastad 广播攻击 (CRT)", m_bytes, {"e": str(used_e), "ns": [str(x) for x in used_ns]})

    # 结果评估
    if unreadable_results:
        log("[-] 扫描完成，未发现可读的明文。但找到了数学上合法的解密结果 (极可能被二次加密)。", "warn")
        return {
            "status": "partial_success",
            "message": "解密成功但结果不可读，已提取 Hex 格式供后续解密",
            "unreadable_results": unreadable_results,
            "logs": logs
        }

    log("[-] 扫描完成，未发现直接可解的明文。可能需要 Factordb/Yafu 等外部工具。", "warn")
    return {"status": "failed", "logs": logs}


# ==========================================
# 数字解析
# ==========================================
_BIGINT_RE = re.compile(r"-?\d+")


def parse_numbers(text: str) -> List[int]:
    nums: List[int] = []
    seen = set()
    for token in _BIGINT_RE.findall(text):
        try:
            v = int(token)
        except ValueError:
            continue
        if v <= 1:
            continue
        if v in seen:
            continue
        seen.add(v)
        nums.append(v)
    return nums


# ==========================================
# 接口
# ==========================================
@router.post("/solve")
async def solve_rsa(file: UploadFile = File(...)):
    try:
        content = await file.read()
    except Exception as e:
        return JSONResponse({"status": "error", "message": f"读取上传文件失败: {e}"}, status_code=400)

    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = content.decode("latin-1", errors="ignore")

    numbers = parse_numbers(text)
    if len(numbers) < 3:
        return JSONResponse({
            "status": "error",
            "message": f"文件中至少需要 3 个整数，实际仅识别到 {len(numbers)} 个。",
            "numbers": [str(x) for x in numbers],
        }, status_code=400)

<<<<<<< HEAD
    if len(numbers) > MAX_NUMBERS:
        return JSONResponse({
            "status": "error",
            "message": (
                f"识别到 {len(numbers)} 个候选参数，超出处理上限 {MAX_NUMBERS}。"
                f"请精简输入，或使用「命名参数」模式直接指定 n/e/c/p/q 等字段。"
            ),
            "numbers": [str(x) for x in numbers[:MAX_NUMBERS]],
        }, status_code=400)

    result = all_in_one_rsa_solver(numbers)
    result["numbers"] = [str(x) for x in numbers]
    return JSONResponse(result)


# ==========================================
# 命名参数智能求解
# ==========================================
class RsaParams(BaseModel):
    n: Optional[str] = None
    p: Optional[str] = None
    q: Optional[str] = None
    e: Optional[str] = None
    c: Optional[str] = None
    d: Optional[str] = None
    phi: Optional[str] = None
    e2: Optional[str] = None
    c2: Optional[str] = None


def _to_int(val: Optional[str]) -> Optional[int]:
    if not val or not val.strip():
        return None
    try:
        return int(val.strip())
    except ValueError:
        return None


def _format_result(m_bytes: bytes, mode: str, params: dict, logs: list) -> dict:
    if is_readable(m_bytes):
        return {
            "status": "success",
            "mode": mode,
            "flag": m_bytes.decode("utf-8", errors="replace"),
            "params": params,
            "logs": logs,
        }
    hex_str = m_bytes.hex()
    return {
        "status": "partial_success",
        "message": "解密成功但结果不可读，已提取 Hex 格式",
        "unreadable_results": [{"mode": mode, "hex": hex_str, "params": params}],
        "logs": logs,
    }


def named_param_solver(params: RsaParams) -> Dict[str, Any]:
    logs: List[Dict[str, str]] = []

    def log(msg: str, type_: str = "info"):
        logs.append({"msg": msg, "type": type_})

    n = _to_int(params.n)
    p = _to_int(params.p)
    q = _to_int(params.q)
    e = _to_int(params.e)
    c = _to_int(params.c)
    d = _to_int(params.d)
    phi = _to_int(params.phi)
    e2 = _to_int(params.e2)
    c2 = _to_int(params.c2)

    present = []
    if n: present.append("n")
    if p: present.append("p")
    if q: present.append("q")
    if e: present.append("e")
    if c: present.append("c")
    if d: present.append("d")
    if phi: present.append("phi")
    if e2: present.append("e2")
    if c2: present.append("c2")

    log(f"[*] 命名参数模式：收到字段 {', '.join(present)}", "system")

    # 推导 n
    if not n and p and q:
        n = p * q
        log("[+] 推导 n = p * q", "info")

    # 推导 phi
    if not phi and p and q:
        phi = (p - 1) * (q - 1)
        log("[+] 推导 phi = (p-1)(q-1)", "info")

    # 推导 d
    if not d and e and phi:
        try:
            d = int(gmpy2.invert(e, phi))
            log("[+] 推导 d = e^(-1) mod phi", "info")
        except Exception:
            pass

    if not c:
        log("[-] 缺少密文 c，无法解密", "error")
        return {"status": "failed", "logs": logs}

    if not n:
        log("[-] 缺少 n（且无法从 p*q 推导），无法解密", "error")
        return {"status": "failed", "logs": logs}

    # 路径1：已知 d，直接解密
    if d:
        log("[>] 使用 m = pow(c, d, n) 直接解密...", "cmd")
        m = pow(c, d, n)
        res = long_to_bytes(int(m))
        return _format_result(res, "直接解密 (已知 d)", {"n": str(n), "d": str(d), "c": str(c)}, logs)

    # 路径2：已知 p, q, e, c
    if p and q and e:
        log("[>] 使用已知 p, q 解密...", "cmd")
        res = attack_known_pq(p, q, e, c)
        if res:
            return _format_result(res, "已知 p, q 直接解密", {"p": str(p), "q": str(q), "e": str(e), "c": str(c)}, logs)
        log("[-] attack_known_pq 失败", "warn")

    # 路径3：共模攻击 n + e + e2 + c + c2
    if e and e2 and c2:
        log("[>] 尝试共模攻击 (e1, e2, c1, c2)...", "cmd")
        res = attack_common_modulus(n, e, e2, c, c2)
        if res:
            return _format_result(res, "共模攻击 (Common Modulus)", {
                "n": str(n), "e1": str(e), "e2": str(e2), "c1": str(c), "c2": str(c2)
            }, logs)
        log("[-] 共模攻击失败", "warn")

    # 路径4：有 e + c，尝试各种攻击
    if e:
        # 小指数
        log("[>] 尝试小指数攻击...", "cmd")
        res = attack_small_e(n, e, c)
        if res:
            return _format_result(res, "小指数攻击", {"n": str(n), "e": str(e), "c": str(c)}, logs)

        # Wiener
        log("[>] 尝试 Wiener 攻击...", "cmd")
        res = attack_wiener(n, e, c)
        if res:
            return _format_result(res, "Wiener攻击", {"n": str(n), "e": str(e), "c": str(c)}, logs)

        # 费马分解
        log("[>] 尝试费马分解...", "cmd")
        res = attack_fermat(n, e, c)
        if res:
            return _format_result(res, "费马分解", {"n": str(n), "e": str(e), "c": str(c)}, logs)

    log("[-] 所有已知路径均未成功，可能需要更多参数或外部工具分解 n。", "warn")
    return {"status": "failed", "logs": logs}


@router.post("/solve_params")
async def solve_rsa_params(params: RsaParams):
    result = named_param_solver(params)
=======
    result = all_in_one_rsa_solver(numbers)
    result["numbers"] = [str(x) for x in numbers]
>>>>>>> 3e068d5fcc9577429dffd86e6c8086867b0817c7
    return JSONResponse(result)