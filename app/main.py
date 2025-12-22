import os
import shutil
import subprocess
import tempfile
import random
import base64
import sys
import glob
import uuid
import cv2
import numpy as np
from typing import Optional, List
from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

app = FastAPI(title="CTF Super Suite")

# 挂载静态资源
# 请确保你的项目结构中有 app/static/assets 文件夹
app.mount("/assets", StaticFiles(directory="app/static/assets"), name="assets")

# === 全局配置 ===
# 临时文件存储路径 (用于存放解包后的 EXE 内容)
TEMP_STORE = "/tmp/ctf_store"
if not os.path.exists(TEMP_STORE):
    os.makedirs(TEMP_STORE)

# === Pydantic 模型 ===
class SelectRequest(BaseModel):
    uid: str
    filename: str

# ==========================================
# 辅助函数
# ==========================================
def recover_magic_number(extracted_dir: str, target_file: str):
    """
    从 struct.pyc 或 PYZ 文件夹中借用头部，修复被剥离的 Magic Number。
    仅用于无头部的入口文件。
    """
    base_candidates = glob.glob(os.path.join(extracted_dir, "struct.pyc"))
    if not base_candidates:
        base_candidates = glob.glob(os.path.join(extracted_dir, "PYZ-00.pyz_extracted", "*.pyc"))
    
    if not base_candidates:
        return False

    try:
        # 读取参考文件的头部 (16 bytes)
        with open(base_candidates[0], "rb") as f:
            magic_header = f.read(16) 
            
        with open(target_file, "rb") as f:
            target_content = f.read()
            
        # 写入头部 + 填充 + 原内容
        with open(target_file, "wb") as f:
            f.write(magic_header[:8])
            f.write(b'\x00' * 8)
            f.write(target_content)
        return True
    except Exception:
        return False

def run_decompile(file_path: str):
    """
    执行反编译核心逻辑：优先 PyCDC，失败转 PyCDAS
    """
    try:
        # 1. 尝试 PyCDC (反编译源码)
        proc = subprocess.run(["pycdc", file_path], capture_output=True, text=True, timeout=15)
        if proc.stdout.strip():
            code = proc.stdout
            if "Unsupported opcode" in code:
                code = f"# Warning: Partial decompilation (Unsupported opcodes found).\n# Logic might be incomplete.\n\n{code}"
            return code
        
        # 2. 尝试 PyCDAS (反汇编)
        proc = subprocess.run(["pycdas", file_path], capture_output=True, text=True, timeout=15)
        return f"# Decompilation failed. Falling back to Disassembly:\n\n{proc.stdout}"
    
    except subprocess.TimeoutExpired:
        return "# Error: Decompilation timed out."
    except Exception as e:
        return f"# System Error: {str(e)}"

# ==========================================
# 核心接口: 分析与反编译
# ==========================================

@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    第一步：接收文件。
    - 如果是 PYC: 直接反编译。
    - 如果是 EXE: 解包，过滤文件列表，返回给前端让用户选择。
    """
    filename = file.filename
    uid = str(uuid.uuid4())
    user_dir = os.path.join(TEMP_STORE, uid)
    os.makedirs(user_dir, exist_ok=True)
    
    save_path = os.path.join(user_dir, filename)
    with open(save_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # 情况 A: Pyc 文件
    if filename.lower().endswith('.pyc'):
        code = run_decompile(save_path)
        shutil.rmtree(user_dir, ignore_errors=True) # 用完即删
        return JSONResponse({"type": "code", "source_code": code})

    # 情况 B: Exe 文件 (PyInstaller)
    elif filename.lower().endswith('.exe'):
        # 定位工具 (使用绝对路径)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        tool_path = os.path.join(current_dir, "pyinstxtractor.py")
        
        if not os.path.exists(tool_path):
            return JSONResponse({"status": "error", "message": "Server missing pyinstxtractor.py"})
            
        # 执行解包
        subprocess.run([sys.executable, tool_path, save_path], cwd=user_dir, capture_output=True, timeout=45)
        
        extracted_folder_name = f"{filename}_extracted"
        full_extract_path = os.path.join(user_dir, extracted_folder_name)
        
        if not os.path.exists(full_extract_path):
            return JSONResponse({"status": "error", "message": "Extraction failed. Is this a valid PyInstaller EXE?"})
            
        # 扫描并过滤文件
        file_list = []
        ignored_exts = ('.dll', '.pyd', '.so', '.exe', '.bin', '.zip')
        ignored_names = ('struct', 'pyiboot01', 'pyi_rth', 'base_library', 'PYZ-00')
        
        for root, dirs, files in os.walk(full_extract_path):
            for f in files:
                f_lower = f.lower()
                # 过滤: 排除二进制库和系统引导文件
                if f_lower.endswith(ignored_exts): continue
                if any(x in f_lower for x in ignored_names): continue
                if f_lower.startswith("pyz-"): continue 

                abs_path = os.path.join(root, f)
                rel_path = os.path.relpath(abs_path, full_extract_path)
                size = os.path.getsize(abs_path)
                
                file_list.append({"name": rel_path, "size": size})
        
        # 按文件大小降序排序 (通常大文件是主逻辑)
        file_list.sort(key=lambda x: x['size'], reverse=True)
        
        return JSONResponse({
            "type": "selection_required", 
            "uid": uid,
            "base_folder": extracted_folder_name,
            "files": file_list
        })
    
    else:
        return JSONResponse({"status": "error", "message": "Unsupported file type"})

@app.post("/api/decompile_selected")
async def decompile_selected(req: SelectRequest):
    """
    第二步：接收用户选择的文件名，进行反编译
    [已修复] 解决重复添加头部导致文件损坏的问题
    """
    user_dir = os.path.join(TEMP_STORE, req.uid)
    if not os.path.exists(user_dir):
        return JSONResponse({"status": "error", "source_code": "# Error: Session expired. Please upload again."})
    
    # 寻找解包目录
    extracted_dirs = glob.glob(os.path.join(user_dir, "*_extracted"))
    if not extracted_dirs:
        return JSONResponse({"status": "error", "source_code": "# Error: Extraction directory missing."})
    
    extract_root = extracted_dirs[0]
    original_file_path = os.path.join(extract_root, req.filename)
    
    # 安全检查 (防止路径穿越)
    if not os.path.abspath(original_file_path).startswith(os.path.abspath(extract_root)):
        return JSONResponse({"status": "error", "source_code": "# Security Warning: Invalid file path."})
    
    if not os.path.exists(original_file_path):
        return JSONResponse({"status": "error", "source_code": f"# Error: File {req.filename} not found."})

    # === 关键修复: 创建临时副本进行操作 ===
    # 这样可以保证每次请求都是基于原始未修改的文件，避免重复修复头部导致文件损坏
    temp_work_file = os.path.join(extract_root, f"temp_{uuid.uuid4()}.pyc")
    shutil.copy(original_file_path, temp_work_file)
    
    try:
        # 智能判断是否需要修复头部
        # 如果文件本身是以 .pyc 结尾的 (如 PYZ 提取出的库文件)，通常已有头部，无需修复
        # 如果文件无后缀 (如主入口脚本)，通常缺失头部，需要修复
        is_standard_pyc = req.filename.lower().endswith('.pyc')
        
        if not is_standard_pyc:
            recover_magic_number(extract_root, temp_work_file)
            
        # 只有在非常必要时才强制改后缀，pycdc 其实不强制要求 .pyc 后缀，但有些环境需要
        # 这里既然已经是副本了，可以安全操作
        
        code = run_decompile(temp_work_file)
        return JSONResponse({"status": "success", "source_code": code})
        
    except Exception as e:
        return JSONResponse({"status": "error", "source_code": f"# System Error: {str(e)}"})
    finally:
        # 清理临时副本
        if os.path.exists(temp_work_file):
            os.remove(temp_work_file)

# ==========================================
# 其他功能模块 (Crack / BWM)
# ==========================================

# --- Snow Cracker ---
def try_crack(file_path: str, password: str) -> Optional[str]:
    try:
        cmd = ["stegsnow", "-C", "-p", password, file_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
        output = result.stdout.strip()
        if output and result.returncode == 0:
            return output
    except Exception:
        pass
    return None

@app.post("/api/crack")
async def crack_snow(file: UploadFile = File(...), custom_dict: Optional[UploadFile] = File(None), keyword: str = Form("flag")):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp_target:
        shutil.copyfileobj(file.file, tmp_target)
        target_path = tmp_target.name

    passwords = []
    if custom_dict:
        content = await custom_dict.read()
        passwords = content.decode('utf-8', errors='ignore').splitlines()
    else:
        passwords = ["test", "password", "123456", "admin", "snow", "ctf"]

    found_password = None
    decrypted_content = None

    for pwd in passwords:
        pwd = pwd.strip()
        if not pwd: continue
        result = try_crack(target_path, pwd)
        if result and keyword in result:
            found_password = pwd
            decrypted_content = result
            break
    os.remove(target_path)
    if found_password:
        return JSONResponse({"status": "success", "password": found_password, "content": decrypted_content})
    else:
        return JSONResponse({"status": "failed", "message": "未能在字典中找到密码或解密内容不包含关键词。"})

# --- Blind Watermark ---
def process_bwm_logic(img_wm_path, img_org_path, seed, alpha, oldseed=False):
    img = cv2.imread(img_org_path)
    img_wm = cv2.imread(img_wm_path)
    if img is None or img_wm is None: raise ValueError("无法读取图片文件")
    h, w = img.shape[0], img.shape[1]
    if img_wm.shape != img.shape: img_wm = cv2.resize(img_wm, (w, h))
    if oldseed: random.seed(seed, version=1)
    else: random.seed(seed)
    m, n = list(range(int(h * 0.5))), list(range(w))
    random.shuffle(m); random.shuffle(n)
    f1 = np.fft.fft2(img); f2 = np.fft.fft2(img_wm)
    rwm = (f2 - f1) / alpha; rwm = np.real(rwm)
    wm = np.zeros(rwm.shape)
    for i in range(int(rwm.shape[0] * 0.5)):
        for j in range(rwm.shape[1]):
            wm[m[i]][n[j]] = np.uint8(rwm[i][j])
    for i in range(int(rwm.shape[0] * 0.5)):
        for j in range(rwm.shape[1]):
            wm[rwm.shape[0] - i - 1][rwm.shape[1] - j - 1] = wm[i][j]
    success, buffer = cv2.imencode('.png', wm)
    if not success: raise ValueError("图片编码失败")
    return base64.b64encode(buffer).decode('utf-8')

@app.post("/api/bwm")
async def crack_bwm(target: UploadFile = File(...), original: UploadFile = File(...), seed: int = Form(20160930), alpha: float = Form(3.0), oldseed: bool = Form(False)):
    tmp_target = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    tmp_org = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    try:
        shutil.copyfileobj(target.file, tmp_target); shutil.copyfileobj(original.file, tmp_org)
        tmp_target.close(); tmp_org.close()
        b64_img = process_bwm_logic(tmp_target.name, tmp_org.name, seed, alpha, oldseed)
        return JSONResponse({"status": "success", "image": f"data:image/png;base64,{b64_img}"})
    except Exception as e:
        return JSONResponse({"status": "error", "message": str(e)}, status_code=500)
    finally:
        if os.path.exists(tmp_target.name): os.remove(tmp_target.name)
        if os.path.exists(tmp_org.name): os.remove(tmp_org.name)

# ==========================================
# SPA 路由 (必须在最后)
# ==========================================
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    if full_path.startswith("api") or full_path.startswith("assets"):
        return JSONResponse({"error": "Not Found"}, status_code=404)
    index_path = 'app/static/index.html'
    if os.path.exists(index_path): return FileResponse(index_path)
    return JSONResponse({"message": "Frontend not built or not found"}, status_code=404)