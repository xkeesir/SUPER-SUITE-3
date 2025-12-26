import base64
import gzip
import binascii
import urllib.parse
import re
import uuid
import hashlib
import zlib
from typing import List, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# === 基础工具 ===

def aggressive_clean(text: str) -> str:
    """暴力清洗：移除所有非 Base64 常见字符"""
    if not isinstance(text, str): return text
    return re.sub(r'[^a-zA-Z0-9+/=]', '', text)


def try_decompress(data: bytes) -> Tuple[bool, bytes]:
    """
    尝试解压 (核心修复：调整顺序，优先处理 Godzilla PHP 的 Raw Deflate)
    """
    if not data: return False, data

    # 1. [高频] 尝试 Raw Deflate (无头压缩，Godzilla PHP 常用)
    # 这解决了“奇怪字符”的问题，因为之前的代码可能忽略了这种无头格式
    try:
        return True, zlib.decompress(data, -zlib.MAX_WBITS)
    except:
        pass

    # 2. 尝试标准 Gzip (Magic: 1F 8B)
    if data.startswith(b'\x1f\x8b'):
        try:
            return True, gzip.decompress(data)
        except:
            pass

    # 3. 尝试标准 Zlib
    try:
        return True, zlib.decompress(data)
    except:
        pass

    return False, data


def format_content(data: bytes) -> str:
    """智能格式化输出"""
    try:
        # 2. 检测 Java 序列化对象
        if data.startswith(b'\xac\xed\x00\x05'):
            return f"[System] Detected Java Serialized Object (Magic: ACED0005)\nSize: {len(data)} bytes\n" + str(
                data[:100])

        # 3. 尝试文本解码
        text = data.decode('utf-8', errors='ignore')

        # 4. 强特征识别 (如果有这些词，一定是文本，忽略乱码比例)
        if "getBasicsInfo" in text or "FileTree" in text or "methodName" in text or "tomcat" in text or "ok" == text:
            clean_text = "".join([c if c.isprintable() or c in '\r\n\t' else '.' for c in text])
            return clean_text

        # 5. 统计可打印字符 (避免输出压缩包乱码)
        printable = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
        # 阈值提高到 0.7，防止二进制被误判为文本
        if len(text) > 0 and (printable / len(text) > 0.7):
            return text

    except:
        pass

    # 6. 二进制视图
    hex_view = binascii.hexlify(data).decode()
    return "[Binary Data / Mixed Content]\nHex View (First 256 bytes):\n" + '\n'.join(
        hex_view[i:i + 64] for i in range(0, min(len(hex_view), 512), 64))


def extract_http_body(data: bytes) -> Tuple[bytes, bool]:
    """提取 HTTP Body"""
    body = data
    is_chunked = False

    if b"\r\n\r\n" in data:
        parts = data.split(b"\r\n\r\n", 1)
        headers = parts[0].lower()
        body = parts[1]
    elif b"\n\n" in data:
        parts = data.split(b"\n\n", 1)
        headers = parts[0].lower()
        body = parts[1]
    else:
        headers = b""

    if b"transfer-encoding: chunked" in headers:
        is_chunked = True
        try:
            # 简易去分块
            new_body = b""
            cursor = 0
            while cursor < len(body):
                end_line = body.find(b"\r\n", cursor)
                if end_line == -1: break
                size_hex = body[cursor:end_line]
                try:
                    chunk_size = int(size_hex, 16)
                except:
                    break
                if chunk_size == 0: break
                cursor = end_line + 2
                new_body += body[cursor: cursor + chunk_size]
                cursor += chunk_size + 2
            if len(new_body) > 0:
                body = new_body
        except:
            pass
    return body, is_chunked


# === 密钥管理 ===

def expand_keys(original_keys: List[Tuple[str, bytes]]) -> List[Tuple[str, bytes]]:
    """
    密钥扩展逻辑
    修复点：保持顺序，优先使用用户提供的原始 Key，避免 PHP 误用 MD5 Key
    """
    key_list = []
    seen = set()

    for name, k_bytes in original_keys:
        # 1. 优先：原始 Key (修复 PHP 乱码的关键)
        if k_bytes not in seen:
            key_list.append((name, k_bytes))
            seen.add(k_bytes)

        # 2. 备选：MD5 变体 (用于 Java 或 特殊 PHP 配置)
        try:
            m = hashlib.md5(k_bytes).hexdigest()

            # Lower 16 (标准 Godzilla)
            k_md5_16 = m[:16].encode()
            if k_md5_16 not in seen:
                key_list.append((f"{name}_MD5_Lower", k_md5_16))
                seen.add(k_md5_16)

            # Upper 16
            k_md5_16_upper = m[:16].upper().encode()
            if k_md5_16_upper not in seen:
                key_list.append((f"{name}_MD5_Upper", k_md5_16_upper))
                seen.add(k_md5_16_upper)
        except:
            pass

    return key_list


# === 加解密核心 ===

def godzilla_php_xor(data: bytes, key: bytes) -> bytes:
    if not data: return b""
    valid_key = key
    while len(valid_key) < 16:
        valid_key += key
    valid_key = valid_key[:16]

    res = bytearray(len(data))
    for i in range(len(data)):
        res[i] = data[i] ^ valid_key[(i + 1) & 15]
    return bytes(res)


def decrypt_aes_try(ciphertext: bytes, key: bytes) -> Tuple[Optional[bytes], str]:
    """AES 单次尝试"""
    # 适配不同长度 Key
    valid_key = key
    if len(valid_key) not in (16, 24, 32):
        valid_key = key[:16].ljust(16, b'\0')

    modes = [
        (AES.MODE_ECB, None, "AES-ECB"),
        (AES.MODE_CBC, b'\x00' * 16, "AES-CBC")
    ]

    for mode, iv, name in modes:
        try:
            cipher = AES.new(valid_key, mode, iv) if iv else AES.new(valid_key, mode)
            plain = cipher.decrypt(ciphertext)
            # 1. PKCS7 Unpad
            try:
                return unpad(plain, AES.block_size), name
            except:
                pass

            # 2. 特征头检测 (Java Class/Serialization) - 不需要 Pad
            if plain.startswith(b'\xca\xfe\xba\xbe') or plain.startswith(b'\xac\xed\x00\x05'):
                return plain, f"{name} (Raw)"

            # 3. 弱兼容 NoPad
            return plain.rstrip(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'), f"{name} (NoPad)"
        except Exception as e:
            continue
    return None, ""


# === 主逻辑 ===

def solve_godzilla(full_data: bytes, keys: List[Tuple[str, bytes]]) -> List[dict]:
    results = []
    body, is_chunked = extract_http_body(full_data)

    # 获取扩展密钥
    expanded_keys = expand_keys(keys)

    payload_candidates = []

    # [A] 原始 Body (Java AES Raw 必备)
    payload_candidates.append(("Raw Body", body))

    # [B] 参数提取 (PHP/Java Base64)
    try:
        body_str = body.decode('utf-8', errors='ignore')
        params = re.findall(r"(?:^|&|\s)([^=\s]+)=([^&\s]*)", body_str)
        for k, val in params:
            if len(val) > 20:
                try:
                    val_clean = aggressive_clean(urllib.parse.unquote(val))
                    b64 = base64.b64decode(val_clean)
                    payload_candidates.append((f"Param '{k}'", b64))
                except:
                    pass
    except:
        pass

    # [C] 响应包正则 (MD5 wrap)
    try:
        matches = re.findall(rb'([a-fA-F0-9]{16})(.+)([a-fA-F0-9]{16})', body, re.DOTALL)
        for _, content, _ in matches:
            # 这里要注意：有时候内容是Raw，有时候是B64
            payload_candidates.append(("Resp MD5 (Raw)", content))
            try:
                b64 = base64.b64decode(aggressive_clean(content.decode()))
                payload_candidates.append(("Resp MD5 (B64)", b64))
            except:
                pass
    except:
        pass

    seen_hashes = set()

    for p_name, payload in payload_candidates:
        if len(payload) < 8: continue

        for k_name, key in expanded_keys:
            real_key = key

            # --- 1. PHP XOR 逻辑 ---
            # 必须放在 AES 之前，且不需要 Offset
            plain_xor = godzilla_php_xor(payload, real_key)
            if plain_xor:
                # 尝试解压，如果解压成功且有特征，则命中
                is_gz, final = try_decompress(plain_xor)
                if _has_strong_signature(final, is_gz):
                    _process_result(final, "PHP_XOR", k_name, p_name, seen_hashes, results, is_gz)
                elif "Resp" in p_name and is_gz:
                    # 响应包如果解压成功，即使没强特征通常也是对的 (比如 ls 命令结果)
                    _process_result(final, "PHP_XOR", k_name, p_name, seen_hashes, results, is_gz)

            # --- 2. AES 逻辑 (含错位爆破) ---
            # 错位爆破非常耗时且容易误报，仅针对 Raw Body 且没找到 PHP 结果时尝试
            # 或者仅当 Payload 长度较大时尝试

            max_offset = 6 if "Raw Body" in p_name else 1

            for offset in range(max_offset):
                current_payload = payload[offset:]
                if len(current_payload) == 0: break
                plain_aes, mode_aes = decrypt_aes_try(current_payload, real_key)

                if plain_aes:
                    is_gz_aes, final_aes = try_decompress(plain_aes)
                    # 只有具备【强特征】才输出，避免 AES 误报产生乱码干扰
                    if _has_strong_signature(final_aes, is_gz_aes):
                        desc = f"{mode_aes} (Offset {offset})"
                        _process_result(final_aes, desc, k_name, p_name, seen_hashes, results, is_gz_aes)
                        break  # 找到正确 Offset 即停止
    return results


def _has_strong_signature(data: bytes, is_gz: bool = False) -> bool:
    """严格特征检测"""
    if data.startswith(b'\xca\xfe\xba\xbe'): return True  # Java Class
    if data.startswith(b'\xac\xed\x00\x05'): return True  # Java Serialization
    if b'<?php' in data[:50]: return True
    if b'methodName' in data: return True

    # 如果是压缩包解压出来的，且看起来像文本，可信度很高
    if is_gz:
        try:
            txt = data.decode('utf-8')
            printable = sum(1 for c in txt if c.isprintable() or c in '\r\n\t')
            if printable / len(txt) > 0.8: return True
        except:
            pass

    return False


def _process_result(final_data: bytes, mode: str, key_name: str, payload_source: str, seen_hashes: set, results: list,
                    is_gz: bool):
    # 再次尝试解压 (Double Check)
    if not is_gz:
        is_gz_new, final_unzip = try_decompress(final_data)
        if is_gz_new: final_data = final_unzip

    score = 0
    desc = "Unknown"

    if final_data.startswith(b'\xca\xfe\xba\xbe'):
        score = 100;
        desc = "Java Class Payload"
    elif final_data.startswith(b'\xac\xed\x00\x05'):
        score = 100;
        desc = "Java Serialized Object"
    elif b'methodName' in final_data:
        score = 100;
        desc = "Godzilla Protocol"
    elif b'<?php' in final_data[:50]:
        score = 90;
        desc = "PHP Code"
    elif is_gz:
        score = 80;
        desc = "Gzip Data"
    else:
        # 文本检测
        try:
            txt = final_data.decode('utf-8')
            printable = sum(1 for c in txt if c.isprintable() or c in '\r\n\t')
            if len(txt) > 5 and (printable / len(txt) > 0.6):
                score = 60;
                desc = "Decrypted Text"
        except:
            pass
    if score >= 60 and len(final_data) > 0:
        h = hashlib.md5(final_data).hexdigest()
        if h in seen_hashes: return
        seen_hashes.add(h)
        results.append({
            "id": str(uuid.uuid4()),
            "title": f"Decrypted: {desc}",
            "type": "success",
            "algo": f"{mode} | Key: {key_name}",
            "source": payload_source,
            "content": format_content(final_data)
        })