FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=non-interactive
ENV TZ=Asia/Shanghai
# 设置镜像源
RUN sed -i "s/ports.ubuntu.com/mirrors.aliyun.com/g" /etc/apt/sources.list && \
    apt update && \
    apt install -y wget

# 获取系统架构并设置JDK URL
RUN ARCH=$(uname -m); \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        echo "Detected ARM64 architecture"; \
        JDK_8_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/8/jdk/aarch64/linux/OpenJDK8U-jdk_aarch64_linux_hotspot_8u472b08.tar.gz"; \
        JDK_11_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/11/jdk/aarch64/linux/OpenJDK11U-jdk_aarch64_linux_hotspot_11.0.29_7.tar.gz"; \
        JDK_17_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/17/jdk/aarch64/linux/OpenJDK17U-jdk_aarch64_linux_hotspot_17.0.17_10.tar.gz"; \
        JDK_21_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/21/jdk/aarch64/linux/OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.9_10.tar.gz"; \
        JDK_25_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/25/jdk/aarch64/linux/OpenJDK25U-jdk_aarch64_linux_hotspot_25.0.1_8.tar.gz"; \
    elif [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then \
        echo "Detected x86_64 architecture"; \
        JDK_8_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/8/jdk/x64/linux/OpenJDK8U-jdk_x64_linux_hotspot_8u472b08.tar.gz"; \
        JDK_11_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/11/jdk/x64/linux/OpenJDK11U-jdk_x64_linux_hotspot_11.0.29_7.tar.gz"; \
        JDK_17_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/17/jdk/x64/linux/OpenJDK17U-jdk_x64_linux_hotspot_17.0.17_10.tar.gz"; \
        JDK_21_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/21/jdk/x64/linux/OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz"; \
        JDK_25_URL="https://mirrors.tuna.tsinghua.edu.cn/Adoptium/25/jdk/x64/linux/OpenJDK25U-jdk_x64_linux_hotspot_25.0.1_8.tar.gz"; \
    else \
        echo "Unsupported architecture: $ARCH"; \
        exit 1; \
    fi; \
    echo "Downloading JDKs..."; \
    mkdir -p /opt/java && \
    wget "$JDK_8_URL" -O /tmp/jdk-8.tar.gz && \
    tar -zxvf /tmp/jdk-8.tar.gz -C /opt/java && \
    mv /opt/java/* /opt/java-8 2>/dev/null || true && \
    rm -rf /opt/java && \
    mkdir -p /opt/java && \
    wget "$JDK_11_URL" -O /tmp/jdk-11.tar.gz && \
    tar -zxvf /tmp/jdk-11.tar.gz -C /opt/java && \
    mv /opt/java/* /opt/java-11 2>/dev/null || true && \
    rm -rf /opt/java && \
    mkdir -p /opt/java && \
    wget "$JDK_17_URL" -O /tmp/jdk-17.tar.gz && \
    tar -zxvf /tmp/jdk-17.tar.gz -C /opt/java && \
    mv /opt/java/* /opt/java-17 2>/dev/null || true && \
    rm -rf /opt/java && \
    mkdir -p /opt/java && \
    wget "$JDK_21_URL" -O /tmp/jdk-21.tar.gz && \
    tar -zxvf /tmp/jdk-21.tar.gz -C /opt/java && \
    mv /opt/java/* /opt/java-21 2>/dev/null || true && \
    rm -rf /opt/java && \
    mkdir -p /opt/java && \
    wget "$JDK_25_URL" -O /tmp/jdk-25.tar.gz && \
    tar -zxvf /tmp/jdk-25.tar.gz -C /opt/java && \
    mv /opt/java/* /opt/java-25 2>/dev/null || true && \
    rm -rf /opt/java && \
    rm -f /tmp/jdk-*.tar.gz

# 验证安装
RUN echo "Verifying JDK installations..." && \
    ls -la /opt/java-* && \
    for version in 8 11 17 21 25; do \
        echo "Java $version:" && \
        ls -d /opt/java-$version/* 2>/dev/null | head -1; \
    done

# 设置默认Java版本为11
RUN ln -sf /opt/java-11 /opt/java-current

# 在标准路径创建符号链接
RUN ln -sf /opt/java-current/bin/java /usr/bin/java && \
    ln -sf /opt/java-current/bin/javac /usr/bin/javac && \
    ln -sf /opt/java-current/bin/jar /usr/bin/jar

# 创建简单的切换脚本 - 使用heredoc格式避免转义问题
RUN cat > /usr/local/bin/jdk << 'EOF'
#!/bin/sh
case $1 in
    8) 
        ln -sf /opt/java-8 /opt/java-current
        ln -sf /opt/java-8/bin/java /usr/bin/java
        ln -sf /opt/java-8/bin/javac /usr/bin/javac
        ln -sf /opt/java-8/bin/jar /usr/bin/jar
        echo "Switched to Java 8"
        ;;
    11)
        ln -sf /opt/java-11 /opt/java-current
        ln -sf /opt/java-11/bin/java /usr/bin/java
        ln -sf /opt/java-11/bin/javac /usr/bin/javac
        ln -sf /opt/java-11/bin/jar /usr/bin/jar
        echo "Switched to Java 11"
        ;;
    17)
        ln -sf /opt/java-17 /opt/java-current
        ln -sf /opt/java-17/bin/java /usr/bin/java
        ln -sf /opt/java-17/bin/javac /usr/bin/javac
        ln -sf /opt/java-17/bin/jar /usr/bin/jar
        echo "Switched to Java 17"
        ;;
    21)
        ln -sf /opt/java-21 /opt/java-current
        ln -sf /opt/java-21/bin/java /usr/bin/java
        ln -sf /opt/java-21/bin/javac /usr/bin/javac
        ln -sf /opt/java-21/bin/jar /usr/bin/jar
        echo "Switched to Java 21"
        ;;
    25)
        ln -sf /opt/java-25 /opt/java-current
        ln -sf /opt/java-25/bin/java /usr/bin/java
        ln -sf /opt/java-25/bin/javac /usr/bin/javac
        ln -sf /opt/java-25/bin/jar /usr/bin/jar
        echo "Switched to Java 25"
        ;;
    list|ls)
        echo "Available Java versions: 8, 11, 17, 21, 25"
        ;;
    current|version)
        echo "Current Java version:"
        java -version 2>&1 | head -1
        ;;
    *)
        echo "Usage: jdk [8|11|17|21|25|list|current]"
        exit 1
        ;;
esac
EOF

COPY sdk /usr/local/bin/sdk

# 需要设置代理否则太慢了
RUN apt install -y zip unzip curl tomcat9 && \
    export https_proxy=http://192.168.1.15:7890 http_proxy=http://192.168.1.15:7890 all_proxy=socks5://192.168.1.15:7890 && \
    curl -s "https://get.sdkman.io" | bash && \
    chmod a+x "$HOME/.sdkman/bin/sdkman-init.sh" && \
    chmod +x /usr/local/bin/jdk && \
    chmod +x /usr/local/bin/sdk && \ 
    sdk install maven 3.8.6 && \
    sdk install maven 3.6.3 && \
    sdk install maven 3.5.4 && \
    sdk install maven 3.3.9 && \
    sdk install gradle 8.5 && \
    sdk install gradle 7.5 && \
    sdk install gradle 6.9 && \
    sdk install gradle 5.6.4 && \
    sdk install gradle 4.10.3 && \
    sdk install gradle 3.5.4

COPY gradle-v /usr/local/bin/gradle-v
COPY mvn-v /usr/local/bin/mvn-v
RUN chmod +x /usr/local/bin/gradle-v && \
    chmod +x /usr/local/bin/mvn-v

RUN cat > /usr/local/bin/mvn << 'EOF'
#!/usr/bin/env sh
set -eu

has_skiptests=0
for arg in "$@"; do
  case "$arg" in
    -DskipTests*|-Dmaven.test.skip*|-Dtest=*) has_skiptests=1 ;;
  esac
done

if [ "$has_skiptests" -eq 0 ]; then
  exec "${MAVEN_HOME:-/root/.sdkman/candidates/maven/current}/bin/mvn" "$@" -DskipTests
fi
exec "${MAVEN_HOME:-/root/.sdkman/candidates/maven/current}/bin/mvn" "$@"
EOF

RUN chmod +x /usr/local/bin/mvn

RUN apt install mysql-client -y

WORKDIR /root
# 设置sdkman环境变量
ENV MAVEN_HOME=/root/.sdkman/candidates/maven/current
ENV GRADLE_HOME=/root/.sdkman/candidates/gradle/current
ENV PATH="/usr/local/bin:$MAVEN_HOME/bin:$GRADLE_HOME/bin:$PATH"
EXPOSE 8080

CMD ["tail", "-f", "/dev/null"]