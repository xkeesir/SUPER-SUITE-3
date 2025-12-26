import re
import base64
import gzip
import binascii
import json
from typing import List, Tuple, Optional, Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# === 冰蝎 Default_Image 协议固定指纹 ===
BEHINDER_IMG_B64 = "iVBORw0KGgoAAAANSUhEUgAAABQAAAAOCAYAAAAvxDzwAAAAAXNSR0IArs4c6QAAAIRlWElmTU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAIAAIdpAAQAAAABAAAAWgAAAAAAAABIAAAAAQAAAEgAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAABSgAwAEAAAAAQAAAA4AAAAAa7cS3QAAAAlwSFlzAAALEwAACxMBAJqcGAAAAVlpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IlhNUCBDb3JlIDYuMC4wIj4KICAgPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICAgICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgICAgICAgICAgeG1sbnM6dGlmZj0iaHR0cDovL25zLmFkb2JlLmNvbS90aWZmLzEuMC8iPgogICAgICAgICA8dGlmZjpPcmllbnRhdGlvbj4xPC90aWZmOk9yaWVudGF0aW9uPgogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KGV7hBwAAAXZJREFUOBGNVE1Lw0AQfRtNRfFUKyqp6E160bSlKv4SwZMeevHqH/EgxaOC/hVbMBoR/LhaP5DWXrxoajbu7LKyaZPUhYQJ897b2TezYZFYGLEiKAgDG4EErCwECYU8VBChSbEWT+OxtAqpcMaSK8rKjSftpAk84mg9X8Hv3kuYWyhhs1iVG2nMIH+oQg2k4x37Z9h/OkE5tyC8YfCCFzSWdlF3d2AxCxpriqYKXrQvseUdYHu6iiD6ARfuTbEczj9baNYOsVGsJArGmkKGa99uu4/Ij+Xl5l88wDfvg2Qdew5+504VlWBxTNAsXc+S4qiBoVgPkIk145gg0cgXWquFFfTCnjzqpGVjQjzk42v/He5sSWnoXdWXfCd2mTLrThlHnT3RlFO49rywArgO3tBYrqPmuIZEPBxqCqV192hsmm0PNx8PkrU2I8ZmsZLaYQIlClJCi1I8uLJyMQ9NInWbiH9XTyTl1cu4QcRPrdAU1/f3Pz+HX/qNrcYjTeaNAAAAAElFTkSuQmCC"

try:
    BEHINDER_IMG_SIGNATURE = base64.b64decode(BEHINDER_IMG_B64)
except:
    BEHINDER_IMG_SIGNATURE = b""


# === 内部工具函数 ===

def aggressive_clean(text: str) -> str:
    if not isinstance(text, str): return text
    return text.replace('\r', '').replace('\n', '').replace(' ', '').strip()


def try_decompress(data: bytes) -> Tuple[bool, bytes]:
    """尝试 GZIP 解压，失败返回原数据"""
    if data.startswith(b'\x1f\x8b'):
        try:
            return True, gzip.decompress(data)
        except:
            return True, data
    return False, data


def extract_strings(data: bytes, min_len=4) -> str:
    """提取二进制中的可打印字符串"""
    result = []
    try:
        pat = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
        matches = pat.findall(data)
        for m in matches:
            s = m.decode()
            if len(s) < 300:
                result.append(s)
            else:
                result.append(s[:300] + "...")
        if not result: return ""
        return "\n".join(result[:50])
    except:
        return ""


def detect_content_type(data: bytes) -> Tuple[bool, str]:
    if not data: return False, "Empty"

    # 1. Java Class File (CA FE BA BE)
    if data.startswith(b'\xca\xfe\xba\xbe'):
        return True, "Java ClassFile (Magic: CAFEBABE)"

    # 2. Java Serialization (AC ED 00 05)
    if data.startswith(b'\xac\xed\x00\x05'):
        return True, "Java Serialized Object"

    # 3. GZIP Compressed
    if data.startswith(b'\x1f\x8b'):
        return True, "GZIP Compressed Data"

    # 4. Image Formats
    if data.startswith(b'\x89PNG\r\n\x1a\n'): return True, "PNG Image"
    if data.startswith(b'\xff\xd8\xff'): return True, "JPEG Image"
    if data.startswith(b'GIF8'): return True, "GIF Image"
    if data.startswith(b'BM'): return True, "BMP Image"

    # 5. JSON / Text
    if try_decode_complex_json(data):
        return True, "JSON Data"

    return False, "Unknown"


def extract_png_steganography(data: bytes) -> Optional[bytes]:
    """
    检测并提取 PNG 图片尾部附加的隐写数据
    改进点：
    1. 使用 rfind 查找最后一个 IEND，防止被缩略图混淆
    2. 模糊匹配 JSON 起始位，防止 CRC 后有垃圾数据
    """
    try:
        # IEND chunk hex: 49 45 4E 44
        # [Fix] 使用 rfind 从后往前找，确保找到主图的结尾
        iend_index = data.rfind(b'\x49\x45\x4E\x44')
        if iend_index == -1:
            return None

        # IEND (4) + CRC (4) = 8 bytes
        payload_start = iend_index + 8

        if payload_start >= len(data):
            return None

        payload = data[payload_start:]

        # 简单校验
        if len(payload) > 2:
            # Case 1: Java Bytecode (Request)
            if b'java/lang' in payload or b'Ljava/' in payload or payload.startswith(b'\xca\xfe\xba\xbe'):
                return payload

            # Case 2: JSON Response (Response) [Enhanced Fix]
            # 不再强制 startswith('{')，而是寻找第一个 '{'
            json_start = payload.find(b'{')
            if json_start != -1:
                # 尝试从 '{' 开始截取，能解码就算成功
                potential_json = payload[json_start:]
                # 快速检查结尾（允许少量尾部空白）
                if b'}' in potential_json:
                    return potential_json

    except:
        pass
    return None


# === 智能 JSON 递归解码逻辑 ===

def recursive_b64_decode(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: recursive_b64_decode(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [recursive_b64_decode(v) for v in obj]
    elif isinstance(obj, str):
        if len(obj) < 2 or not re.match(r'^[A-Za-z0-9+/=]+$', obj):
            return obj
        try:
            decoded_bytes = base64.b64decode(obj)
            try:
                decoded_str = decoded_bytes.decode('utf-8')
            except:
                return obj
            stripped = decoded_str.strip()
            if (stripped.startswith('{') and stripped.endswith('}')) or \
                    (stripped.startswith('[') and stripped.endswith(']')):
                try:
                    inner_json = json.loads(stripped)
                    return recursive_b64_decode(inner_json)
                except:
                    pass
            return decoded_str
        except:
            pass
    return obj


def try_decode_complex_json(data: bytes) -> Optional[str]:
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        # [Fix] 宽松模式：只要包含完整的 {} 结构即可
        # 提取最外层的 JSON 对象
        match = re.search(r'(\{.*\})', text, re.DOTALL)
        if match:
            text = match.group(1)
        elif not ((text.startswith('{') and text.endswith('}')) or (text.startswith('[') and text.endswith(']'))):
            return None

        json_obj = json.loads(text)
        decoded_obj = recursive_b64_decode(json_obj)
        return json.dumps(decoded_obj, indent=2, ensure_ascii=False)
    except:
        return None


# === 核心解密算法 ===

def decrypt_xor_variants(data: bytes, key: bytes) -> List[Tuple[str, bytes]]:
    results = []
    if len(key) < 16: return results

    try:
        out_v1 = bytearray(len(data))
        key_bytes = key
        for i in range(len(data)):
            k_idx = (i + 1) & 15
            out_v1[i] = data[i] ^ key_bytes[k_idx]
        results.append(("XOR(i+1)", bytes(out_v1)))
    except:
        pass

    try:
        out_v2 = bytearray(len(data))
        for i in range(len(data)):
            k_idx = i % 16
            out_v2[i] = data[i] ^ key[k_idx]
        results.append(("XOR(Standard)", bytes(out_v2)))
    except:
        pass

    return results


def decrypt_aes_std(data: bytes, key: bytes) -> Tuple[Optional[bytes], bool]:
    try:
        if len(data) == 0: return None, False
        rem = len(data) % 16
        if rem != 0:
            if len(data) > 16:
                data = data[:-rem]
            else:
                return None, False
        cipher = AES.new(key, AES.MODE_ECB)
        plain = cipher.decrypt(data)
        try:
            return unpad(plain, AES.block_size), True
        except:
            return plain.rstrip(b'\0'), False
    except:
        return None, False


def decrypt_aes_magic(data: bytes, key: bytes) -> Tuple[Optional[bytes], bool]:
    try:
        k_prefix = key[:2]
        try:
            magic_num = int(k_prefix, 16) % 16
        except:
            return None, False

        if magic_num > 0:
            if len(data) <= magic_num: return None, False
            data_trimmed = data[:-magic_num]
        else:
            data_trimmed = data

        try:
            ciphertext = base64.b64decode(data_trimmed)
        except:
            return None, False

        return decrypt_aes_std(ciphertext, key)
    except:
        return None, False


def decrypt_default_image(data: bytes) -> Optional[bytes]:
    if len(data) <= 966:
        return None

    potential_payload = data[966:]

    is_image_header = False
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        is_image_header = True
    elif data.startswith(b'\xff\xd8\xff'):
        is_image_header = True
    elif data.startswith(b'GIF8'):
        is_image_header = True
    elif data.startswith(b'BM'):
        is_image_header = True
    elif BEHINDER_IMG_SIGNATURE and data.startswith(BEHINDER_IMG_SIGNATURE[:16]):
        is_image_header = True

    is_valid_payload = False
    if potential_payload.startswith(b'\x1f\x8b'):
        is_valid_payload = True
    elif potential_payload.startswith(b'\xca\xfe\xba\xbe'):
        is_valid_payload = True
    elif potential_payload.startswith(b'\xac\xed\x00\x05'):
        is_valid_payload = True

    if is_valid_payload:
        return potential_payload

    if is_image_header:
        return potential_payload

    return None


def decrypt_default_json(data: bytes) -> Optional[bytes]:
    if len(data) < 30: return None
    sliced = data[26:-3]
    try:
        s = sliced.decode('utf-8', errors='ignore')
        s = s.replace('<', '+').replace('>', '/')
        return base64.b64decode(s)
    except:
        return None


# === 流量处理逻辑 ===

def unchunk_http(data: bytes) -> bytes:
    if not data or len(data) < 3: return data
    result = bytearray()
    cursor = 0
    total_len = len(data)
    try:
        while cursor < total_len:
            eol = data.find(b'\r\n', cursor)
            if eol == -1: return bytes(result) if result else data
            line = data[cursor:eol]
            if b';' in line: line = line.split(b';')[0]
            try:
                chunk_size = int(line, 16)
            except:
                return bytes(result) if result else data
            if chunk_size == 0: break
            data_start = eol + 2
            data_end = data_start + chunk_size
            if data_end > total_len:
                result.extend(data[data_start:])
                break
            result.extend(data[data_start:data_end])
            cursor = data_end + 2
        return bytes(result)
    except:
        return data


def split_behinder_stream(data: bytes) -> List[bytes]:
    bodies = []
    cursor = 0
    total_len = len(data)
    while cursor < total_len:
        header_end = data.find(b"\r\n\r\n", cursor)
        if header_end == -1:
            remain = data[cursor:]
            if remain.strip(): bodies.append(remain)
            break
        header_bytes = data[cursor:header_end]
        header_str = header_bytes.decode(errors='ignore').lower()
        body_start = header_end + 4
        consumed = 0
        current_body = b""
        if "transfer-encoding: chunked" in header_str:
            next_http = data.find(b"HTTP/1.", body_start)
            if next_http != -1:
                raw_chunk = data[body_start:next_http]
                consumed = next_http - cursor
            else:
                raw_chunk = data[body_start:]
                consumed = total_len - cursor
            current_body = unchunk_http(raw_chunk)
        elif "content-length:" in header_str:
            try:
                match = re.search(r'content-length:\s*(\d+)', header_str)
                length = int(match.group(1)) if match else 0
                current_body = data[body_start: body_start + length]
                consumed = (body_start + length) - cursor
            except:
                consumed = body_start - cursor
        else:
            next_http = data.find(b"HTTP/1.", body_start)
            if next_http != -1:
                current_body = data[body_start:next_http]
                consumed = next_http - cursor
            else:
                current_body = data[body_start:]
                consumed = total_len - cursor
        if current_body: bodies.append(current_body)
        if consumed <= 0: consumed = 1
        cursor += consumed
    return bodies


def process_behinder_json_response(data: bytes, key: bytes) -> Tuple[bool, bytes, str]:
    try:
        text = data.strip().decode('utf-8', errors='ignore')
        if not ('"status":' in text and '"msg":' in text):
            return False, data, ""
        match = re.search(r'"msg"\s*:\s*"([^"]+)"', text)
        if not match: return False, data, ""
        msg_b64 = match.group(1)
        try:
            msg_cipher = base64.b64decode(msg_b64)
        except:
            return False, data, ""

        img_plain = decrypt_default_image(msg_cipher)
        if img_plain:
            _, final_img = try_decompress(img_plain)
            return True, final_img, "[Behinder Protocol] (Image)"

        plain, success = decrypt_aes_std(msg_cipher, key)
        if success and plain:
            _, final_data = try_decompress(plain)
            return True, final_data, "[Behinder Protocol] (AES)"

        xor_results = decrypt_xor_variants(msg_cipher, key)
        for algo_name, plain_xor in xor_results:
            is_gz, final_xor = try_decompress(plain_xor)
            is_valid, _ = detect_content_type(final_xor)
            if is_gz or is_valid:
                return True, final_xor, f"[Behinder Protocol] ({algo_name})"
    except:
        pass
    return False, data, ""


def solve_behinder(full_data: bytes, password: str, keys: List[Tuple[str, bytes]]) -> List[dict]:
    results = []
    bodies = split_behinder_stream(full_data)

    for idx, body in enumerate(bodies):
        candidates = [{"type": "Raw", "data": body}]
        try:
            body_str = aggressive_clean(body.decode(errors='ignore'))
            if body_str:
                b64 = base64.b64decode(body_str)
                candidates.append({"type": "Base64", "data": b64})
        except:
            pass

        solved = False

        for cand in candidates:
            payload = cand["data"]
            source_type = cand["type"]

            # ==================================================
            # 策略：优先检测 PNG 隐写 (Steganography)
            # ==================================================
            if payload.startswith(b'\x89PNG'):
                stego_data = extract_png_steganography(payload)
                if stego_data:
                    # 尝试解析为 JSON (针对响应包)
                    json_view = try_decode_complex_json(stego_data)

                    if json_view:
                        results.append({
                            "id": f"behinder-{idx}-png-json",
                            "title": f"Packet #{idx + 1} (Image + JSON Response)",
                            "type": "success",
                            "algo": "Steganography (JSON)",
                            "content": json_view
                        })
                        solved = True
                        continue
                    else:
                        # 否则按二进制/文本展示 (针对请求包)
                        _, content_type = detect_content_type(stego_data)
                        content_view = extract_strings(stego_data)

                        if "ClassFile" in content_type:
                            hex_head = binascii.hexlify(stego_data[:8]).decode()
                            content_view = f"[{content_type}]\nMagic Header: {hex_head}\n\n{content_view}"

                        results.append({
                            "id": f"behinder-{idx}-png-stego",
                            "title": f"Packet #{idx + 1} (Image + Java Request)",
                            "type": "success",
                            "algo": "Steganography (Java)",
                            "content": content_view
                        })
                        solved = True
                        continue

            # ==================================================
            # 策略：尝试 Key 相关算法 (XOR, AES, AES_Magic)
            # ==================================================

            for k_name, key in keys:
                decryption_attempts = []

                # 1. XOR
                xor_vars = decrypt_xor_variants(payload, key)
                for algo_subname, plain_xor in xor_vars:
                    decryption_attempts.append((algo_subname, plain_xor, False))

                # 2. AES
                plain_aes, valid_aes = decrypt_aes_std(payload, key)
                if plain_aes: decryption_attempts.append(("AES", plain_aes, valid_aes))

                # 3. AES Magic
                plain_magic, valid_magic = decrypt_aes_magic(payload, key)
                if plain_magic: decryption_attempts.append(("AES_Magic", plain_magic, valid_magic))

                for algo_name, plain_bytes, is_strong_valid in decryption_attempts:
                    if not plain_bytes: continue

                    is_gz, final = try_decompress(plain_bytes)

                    is_double, inner, wrapper_proto = process_behinder_json_response(final, key)

                    if is_double:
                        json_view = try_decode_complex_json(inner)
                        content_view = json_view if json_view else extract_strings(inner)
                        results.append({
                            "id": f"behinder-{idx}-{algo_name}",
                            "title": f"Packet #{idx + 1} (Wrapper)",
                            "type": "success",
                            "algo": f"{algo_name} > {wrapper_proto}",
                            "content": f"=== Wrapper ===\n{extract_strings(final)}\n\n=== Payload ===\n{content_view}"
                        })
                        solved = True

                    else:
                        is_valid, type_desc = detect_content_type(final)
                        force_show = False
                        if "XOR" in algo_name and source_type == "Base64":
                            if "ClassFile" in type_desc or "GZIP" in type_desc:
                                force_show = True

                        if is_strong_valid or is_valid or force_show:
                            content_str = ""
                            json_view = try_decode_complex_json(final)

                            if json_view:
                                content_str = json_view
                            elif "ClassFile" in type_desc:
                                hex_head = binascii.hexlify(final[:8]).decode()
                                content_str = f"[{type_desc}]\nMagic Header: {hex_head}\n(Note: 'cafebabe' often appears as '漱壕' in GBK)\n\n=== Strings extracted ===\n{extract_strings(final)}"
                            else:
                                content_str = extract_strings(final)

                            if content_str == aggressive_clean(body.decode(errors='ignore')):
                                continue

                            results.append({
                                "id": f"behinder-{idx}-{algo_name}",
                                "title": f"Packet #{idx + 1} ({type_desc})",
                                "type": "success",
                                "algo": f"{source_type} > {algo_name}",
                                "content": content_str
                            })
                            solved = True

            # ==================================================
            # 兜底尝试
            # ==================================================
            if not solved:
                res_img = decrypt_default_image(payload)
                if res_img:
                    _, final_img_payload = try_decompress(res_img)
                    is_valid_img, img_type = detect_content_type(final_img_payload)

                    if "ClassFile" in img_type or "GZIP" in img_type or "Serialized" in img_type:
                        content_view = extract_strings(final_img_payload)
                        if "ClassFile" in img_type:
                            hex_head = binascii.hexlify(final_img_payload[:8]).decode()
                            content_view = f"[{img_type}]\nMagic Header: {hex_head}\n\n{content_view}"

                        results.append({
                            "id": f"behinder-{idx}-img",
                            "title": f"Packet #{idx + 1} (Image Proto)",
                            "type": "success",
                            "algo": "Default_Image",
                            "content": content_view
                        })
                        solved = True

                res_json_proto = decrypt_default_json(payload)
                if res_json_proto:
                    view = try_decode_complex_json(res_json_proto) or extract_strings(res_json_proto)
                    results.append({
                        "id": f"behinder-{idx}-json",
                        "title": f"Packet #{idx + 1} (Default JSON)",
                        "type": "success",
                        "algo": "Default_JSON",
                        "content": view
                    })
                    solved = True

    if not results:
        return []

    unique_results = []
    seen = set()
    for r in results:
        k = r['content'][:100]
        if k not in seen:
            seen.add(k)
            unique_results.append(r)
    return unique_results