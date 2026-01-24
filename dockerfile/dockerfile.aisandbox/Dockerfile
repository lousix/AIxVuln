FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=non-interactive
ENV TZ=Asia/ShangHai
COPY data /data
RUN sed -i "s/ports.ubuntu.com/mirrors.aliyun.com/g" /etc/apt/sources.list && \
apt update &&\
apt install -y php gcc python3 dirsearch nmap sqlmap python3-pip netcat openjdk-8-jdk unzip zip vim curl wget git mysql-client ssh ftp net-Tools &&\
pip3 install -i https://mirrors.aliyun.com/pypi/simple/ beautifulsoup4 requests cryptography pycryptodome httpx
WORKDIR /tmp
RUN ln -s /data/phpgcc /bin/phpgcc

CMD ["python3", "/data/SandboxServer.py"]
