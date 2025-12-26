import os
import shutil
import uuid
import hashlib
import base64
import re
import glob
from typing import List, Optional, Dict, Tuple, Any
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from scapy.all import rdpcap, IP, TCP, Raw

try:
    from .traffic_godzilla import solve_godzilla
    from .traffic_behinder import solve_behinder
except ImportError:
    from traffic_godzilla import solve_godzilla
    from traffic_behinder import solve_behinder

router = APIRouter(prefix="/api/traffic", tags=["traffic"])

BASE_TEMP_DIR = "/tmp/ctf_traffic"
UPLOAD_DIR = os.path.join(BASE_TEMP_DIR, "uploads")
STREAMS_DIR = os.path.join(BASE_TEMP_DIR, "streams")

for d in [BASE_TEMP_DIR, UPLOAD_DIR, STREAMS_DIR]:
    if not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


# === Models ===
class PacketInfo(BaseModel):
    id: int
    stream_id: str
    time: float
    src: str
    dst: str
    method: str
    uri: str
    payload_len: int
    raw_payload: str
    shell_type: str


class StreamMessage(BaseModel):
    seq: int
    type: str
    header_summary: str
    raw_b64: str
    content_len: int


class DecryptRequest(BaseModel):
    payload_b64: str
    tool: str = "godzilla"
    script_type: str = "jsp"
    encode_type: str = "aes"
    # password removed
    secret_key: str


# === 核心工具 ===

def get_keys_to_try(user_input_key: str) -> List[Tuple[str, bytes]]:
    """
    根据用户输入的 Key 生成候选密钥列表。
    用户可能输入的是：密码原文、MD5字符串、Raw Key
    """
    candidates = []
    if not user_input_key: return candidates

    # 1. 假设输入的是密码原文 -> 尝试 MD5(Pass)
    try:
        m = hashlib.md5()
        m.update(user_input_key.encode('utf-8'))
        md5_key = m.hexdigest()[:16].encode('utf-8')
        candidates.append(("MD5(Input)", md5_key))
    except:
        pass

    # 2. 假设输入的是 Raw Key (直接使用)
    raw_key = user_input_key.encode('utf-8')
    if len(raw_key) >= 16:
        candidates.append(("Raw Key", raw_key[:16]))
    else:
        # 补齐
        candidates.append(("Raw Key (Padded)", raw_key.ljust(16, b'\0')))

    return candidates


def split_http_messages(data: bytes) -> List[Dict[str, Any]]:
    # ... (保持之前的鲁棒性切分逻辑不变) ...
    messages = []
    if not data: return messages
    cursor = 0
    total_len = len(data)
    seq = 0
    http_methods = [b'GET ', b'POST ', b'PUT ', b'HEAD ', b'OPTIONS ', b'HTTP/']

    while cursor < total_len:
        header_end = data.find(b"\r\n\r\n", cursor)
        if header_end == -1 or (header_end - cursor) > 8192:
            remain = data[cursor:]
            msg_type = "req"
            if remain.strip().startswith(b'HTTP/'): msg_type = "resp"
            messages.append({
                "seq": seq, "type": msg_type,
                "header_summary": f"Raw Segment ({len(remain)} bytes)",
                "raw_data": remain, "length": len(remain)
            })
            break

        header_bytes = data[cursor:header_end]
        try:
            header_str = header_bytes.decode(errors='ignore')
        except:
            header_str = ""

        first_line = header_str.split('\r\n')[0]
        is_response = first_line.upper().startswith("HTTP/")
        msg_type = "resp" if is_response else "req"

        body_start = header_end + 4
        next_cursor = total_len

        cl_match = re.search(r'Content-Length:\s*(\d+)', header_str, re.IGNORECASE)
        if cl_match:
            content_len = int(cl_match.group(1))
            next_cursor = body_start + content_len
        elif "Transfer-Encoding: chunked" in header_str:
            best_next = total_len
            for m in http_methods:
                idx = data.find(m, body_start + 10)
                if idx != -1 and idx < best_next: best_next = idx
            next_cursor = best_next
        else:
            best_next = total_len
            for m in http_methods:
                idx = data.find(m, body_start + 5)
                if idx != -1 and idx < best_next: best_next = idx
            next_cursor = best_next

        if next_cursor > total_len: next_cursor = total_len
        if next_cursor <= cursor: next_cursor = total_len

        full_packet = data[cursor:next_cursor]
        messages.append({
            "seq": seq, "type": msg_type,
            "header_summary": first_line[:60],
            "raw_data": full_packet, "length": len(full_packet)
        })
        cursor = next_cursor
        seq += 1
    return messages


def parse_pcap_streams(file_path: str) -> List[PacketInfo]:
    # ... (保持之前的解析逻辑不变) ...
    try:
        scapy_packets = rdpcap(file_path)
    except Exception as e:
        return []
    flows: Dict[tuple, bytearray] = {}
    flow_meta: Dict[tuple, dict] = {}
    flow_order = []
    for pkt in scapy_packets:
        if IP in pkt and TCP in pkt and Raw in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            payload = pkt[Raw].load
            if not payload: continue
            endpoint_a = (src, sport)
            endpoint_b = (dst, dport)
            endpoints = sorted([endpoint_a, endpoint_b])
            key = (endpoints[0], endpoints[1])
            if key not in flows:
                flows[key] = bytearray()
                flow_meta[key] = {"time": float(pkt.time), "src": src, "dst": dst}
                flow_order.append(key)
            flows[key].extend(payload)
    try:
        files = glob.glob(os.path.join(STREAMS_DIR, "*"))
        for f in files: os.remove(f)
    except:
        pass
    packets_list = []
    for key in flow_order:
        data = flows[key]
        meta = flow_meta[key]
        method = "TCP"
        uri = ""
        try:
            head_preview = data[:2048].decode(errors='ignore')
            if "HTTP/" in head_preview:
                lines = head_preview.split('\r\n')
                found_req = False
                for line in lines:
                    parts = line.split(' ')
                    if len(parts) >= 2 and parts[0] in ['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS']:
                        method = parts[0];
                        uri = parts[1];
                        found_req = True;
                        break
                if not found_req: method = "RESP"; uri = "(Response First)"
        except:
            pass
        stream_id = str(uuid.uuid4())
        stream_file_path = os.path.join(STREAMS_DIR, stream_id)
        with open(stream_file_path, "wb") as f:
            f.write(data)
        shell_type = "unknown"
        if uri:
            lower = uri.lower()
            if ".php" in lower:
                shell_type = "php"
            elif ".jsp" in lower:
                shell_type = "jsp"
            elif ".aspx" in lower:
                shell_type = "aspx"
        packets_list.append(PacketInfo(
            id=len(packets_list), stream_id=stream_id,
            time=meta["time"], src=meta["src"], dst=meta["dst"],
            method=method, uri=uri, payload_len=len(data), raw_payload="", shell_type=shell_type
        ))
    return packets_list


# === API 路由 ===

@router.post("/analyze", response_model=List[PacketInfo])
async def analyze_pcap(file: UploadFile = File(...)):
    filename = str(uuid.uuid4()) + ".pcap"
    file_path = os.path.join(UPLOAD_DIR, filename)
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    try:
        return parse_pcap_streams(file_path)
    except Exception as e:
        return []
    finally:
        if os.path.exists(file_path): os.remove(file_path)


@router.get("/stream_messages/{stream_id}", response_model=List[StreamMessage])
async def get_stream_messages(stream_id: str):
    stream_file_path = os.path.join(STREAMS_DIR, stream_id)
    if not os.path.exists(stream_file_path):
        raise HTTPException(status_code=404, detail="Stream data not found")
    with open(stream_file_path, "rb") as f:
        full_data = f.read()
    msgs = split_http_messages(full_data)
    result = []
    for m in msgs:
        try:
            b64 = base64.b64encode(m['raw_data']).decode()
        except:
            b64 = ""
        result.append(StreamMessage(
            seq=m['seq'], type=m['type'], header_summary=m['header_summary'],
            raw_b64=b64, content_len=m['length']
        ))
    return result


@router.post("/decrypt_shell")
async def decrypt_traffic(req: DecryptRequest):
    try:
        if not req.payload_b64: return {"status": "error", "content": []}
        full_data = base64.b64decode(req.payload_b64)

        # 将 secret_key 作为输入生成候选密钥
        # 兼容用户输入"密码原文"或"MD5 Key"的情况
        keys = get_keys_to_try(req.secret_key)

        results = []
        if req.tool.lower() == "godzilla":
            # 无需传递 password
            results = solve_godzilla(full_data, keys)
        elif req.tool.lower() == "behinder":
            results = solve_behinder(full_data, "", keys)  # behider 接口需保留空串占位符或修改 behider 签名

        if not results:
            try:
                body = full_data
                if b"\r\n\r\n" in full_data:
                    parts = full_data.split(b"\r\n\r\n", 1)
                    if len(parts) > 1: body = parts[1]
                if len(body) > 0:
                    text_preview = body[:1000].decode('utf-8', errors='ignore')
                    printable_ratio = sum(1 for c in text_preview if c.isprintable() or c in '\r\n\t') / len(
                        text_preview)
                    if printable_ratio > 0.8:
                        results.append({
                            "id": "raw-text", "title": "Raw Text (Unencrypted)",
                            "type": "neutral", "algo": "None",
                            "content": body.decode('utf-8', errors='ignore')
                        })
            except:
                pass

        if results:
            return {"status": "success", "content": results}
        else:
            return {"status": "error", "content": []}
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "content": []}