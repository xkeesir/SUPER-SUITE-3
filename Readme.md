# SUPER-SUITE-3

> 面向 CTF Misc 和流量分析的一站式工具套件。

Demo：
👉 http://116.62.41.228:8000

## ✨ Features

- ✅ **超级大解码**：支持多种编码格式与**嵌套编码**；一次粘贴，快速出结果  
- ✅ **超级 Snow 爆破**：全图形化的 Snow 隐写提取与密码爆破  
- ✅ **超级 JWT**：JWT 生成 / 编辑 / 密钥爆破 / 时间戳工具一条龙  
- ✅ **超级加解密**：图形化 AES / DES / Dabbit 等多算法加解密  
- ✅ **超级 StegSolve（LSB 提取）**：支持多通道、位顺序、扫描方向组合检索关键字（如 `flag`）  
- ✅ **超级 FTT 水印提取**：从图像中提取 FTT 水印；支持对比度 / 灰度自由调节  
- ✅ **超级双图隐写分析**：支持 BWM / XOR 等需要原图参与的水印/隐写算法分析  
- ✅ **超级 PYC 反编译**：优雅反编译 `.pyc` 以及 PyInstaller 打包的 `exe`  
- ✅ **超级二维码**：双引擎识别；支持 GIF 逐帧解码；支持修复定位点后再解码  
- ✅ **超级WS流量分析**：实现对冰蝎4.0和哥斯拉默认加密流量一站式分析，采用强大的可读性竞争算法，再也无需选择加密方式。

> 目标：把常见 Misc 工具链整合到一个套件里，减少重复配环境和来回切工具。
<img width="2879" height="1526" alt="image" src="https://github.com/user-attachments/assets/6a8bbd5a-2194-4e8f-bbf1-e2c78071ed7b" />

## 📦 Installation

### Docker 直接运行（推荐）

**依赖：**
- Docker

```bash
# 1) 构建镜像
docker build -t super-suite3 .

# 2) 运行容器（将服务映射到本机 8000 端口）
docker run -d -p 8000:8000 --name super-suite3 super-suite3

```

**启动后访问：**

- http://127.0.0.1:8000/
