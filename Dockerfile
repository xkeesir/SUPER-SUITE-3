# ========== Stage 1: 构建 PyCDC (C++ 编译阶段) ==========
FROM python:3.11-slim AS builder

# 安装编译所需的工具链 (去除 git，因为我们改用本地 COPY)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 编译 PyCDC
WORKDIR /build

# [修改点]：不再在容器内 git clone，而是直接复制本地下载好的源码
# 这能完美避开容器内的网络连接问题
COPY pycdc .

RUN cmake . && \
    make

# ========== Stage 2: 最终运行环境 ==========
FROM python:3.11-slim

WORKDIR /code

# 1. 安装系统级依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends stegsnow && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. 从 Stage 1 复制编译好的二进制文件
COPY --from=builder /build/pycdc /usr/local/bin/pycdc
COPY --from=builder /build/pycdas /usr/local/bin/pycdas

# 赋予执行权限
RUN chmod +x /usr/local/bin/pycdc /usr/local/bin/pycdas

# 3. 配置虚拟环境
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# 4. 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. 复制项目代码
COPY app ./app

# 6. 启动服务
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]