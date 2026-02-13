FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=non-interactive
ENV TZ=Asia/Shanghai

# 设置镜像源（兼容 amd64 用 archive.ubuntu.com、arm64 用 ports.ubuntu.com）
RUN sed -i "s|http://archive.ubuntu.com|http://mirrors.aliyun.com|g" /etc/apt/sources.list && \
    sed -i "s|http://security.ubuntu.com|http://mirrors.aliyun.com|g" /etc/apt/sources.list && \
    sed -i "s|http://ports.ubuntu.com|http://mirrors.aliyun.com|g" /etc/apt/sources.list && \
    apt update && \
    apt install -y wget zip unzip curl tomcat9 mysql-client

# 安装 SDKMAN（跳过 native CLI 下载，避免 404）
COPY sdk /usr/local/bin/sdk
ENV SDKMAN_DIR="/root/.sdkman"
RUN bash -c "export SDKMAN_NATIVE=false && curl -s https://get.sdkman.io | bash" && \
    mkdir -p "$SDKMAN_DIR/etc" && \
    echo "sdkman_auto_answer=true" >> "$SDKMAN_DIR/etc/config" && \
    echo "sdkman_auto_selfupdate=false" >> "$SDKMAN_DIR/etc/config" && \
    echo "sdkman_selfupdate_feature=false" >> "$SDKMAN_DIR/etc/config" && \
    chmod a+x "$SDKMAN_DIR/bin/sdkman-init.sh" && \
    chmod +x /usr/local/bin/sdk

# 通过 SDKMAN 安装 JDK（Temurin）
# SDKMAN 自动处理架构检测（aarch64/x86_64）
RUN sdk install java 8.0.442-tem && \
    sdk install java 11.0.26-tem && \
    sdk install java 17.0.14-tem && \
    sdk install java 21.0.6-tem && \
    sdk install java 24.0.1-tem

# 设置默认 Java 为 11
RUN sdk default java 11.0.26-tem

# SDKMAN candidates 目录
ENV JAVA_CANDIDATES_DIR="/root/.sdkman/candidates/java"

# 在标准路径创建符号链接（指向 SDKMAN current）
RUN ln -sf ${JAVA_CANDIDATES_DIR}/current/bin/java /usr/bin/java && \
    ln -sf ${JAVA_CANDIDATES_DIR}/current/bin/javac /usr/bin/javac && \
    ln -sf ${JAVA_CANDIDATES_DIR}/current/bin/jar /usr/bin/jar

# jdk 切换脚本 — 通过 SDKMAN 切换并更新 /usr/bin 符号链接
RUN cat > /usr/local/bin/jdk << 'SCRIPT'
#!/bin/bash
CANDIDATES_DIR="/root/.sdkman/candidates/java"

update_links() {
    ln -sf "${CANDIDATES_DIR}/current/bin/java"  /usr/bin/java
    ln -sf "${CANDIDATES_DIR}/current/bin/javac" /usr/bin/javac
    ln -sf "${CANDIDATES_DIR}/current/bin/jar"   /usr/bin/jar
}

# 从已安装版本中查找匹配的完整版本号
find_version() {
    local major="$1"
    ls -1 "$CANDIDATES_DIR" 2>/dev/null | grep -v current | while read dir; do
        case "$dir" in
            ${major}.0.*-tem|${major}.0.*-open|${major}.*-tem|${major}.*-open) echo "$dir"; return ;;
        esac
    done
}

case "$1" in
    8|11|17|21|24)
        ver=$(find_version "$1")
        if [ -z "$ver" ]; then
            echo "Java $1 not installed. Available:"
            ls -1 "$CANDIDATES_DIR" | grep -v current
            exit 1
        fi
        ln -sfn "${CANDIDATES_DIR}/${ver}" "${CANDIDATES_DIR}/current"
        update_links
        echo "Switched to Java $1 ($ver)"
        java -version 2>&1 | head -1
        ;;
    list|ls)
        echo "Installed Java versions:"
        ls -1 "$CANDIDATES_DIR" | grep -v current
        echo ""
        echo "Current: $(basename "$(readlink -f "${CANDIDATES_DIR}/current")")"
        ;;
    current|version)
        echo "Current: $(basename "$(readlink -f "${CANDIDATES_DIR}/current")")"
        java -version 2>&1 | head -1
        ;;
    *)
        echo "Usage: jdk [8|11|17|21|24|list|current]"
        exit 1
        ;;
esac
SCRIPT
RUN chmod +x /usr/local/bin/jdk

# 通过 SDKMAN 安装 Maven 和 Gradle 多版本
RUN sdk install maven 3.8.6 && \
    sdk install maven 3.6.3 && \
    sdk install maven 3.5.4 && \
    sdk install maven 3.3.9 && \
    sdk install gradle 8.5 && \
    sdk install gradle 7.5 && \
    sdk install gradle 6.9 && \
    sdk install gradle 5.6.4 && \
    sdk install gradle 4.10.3

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

# 验证安装
RUN echo "=== JDK versions ===" && jdk list && \
    echo "=== Current Java ===" && java -version 2>&1 && \
    echo "=== Maven ===" && ${SDKMAN_DIR}/candidates/maven/current/bin/mvn --version 2>&1 | head -1 && \
    echo "=== Gradle ===" && ${SDKMAN_DIR}/candidates/gradle/current/bin/gradle --version 2>&1 | head -1

WORKDIR /root
# 设置环境变量
ENV JAVA_HOME=/root/.sdkman/candidates/java/current
ENV MAVEN_HOME=/root/.sdkman/candidates/maven/current
ENV GRADLE_HOME=/root/.sdkman/candidates/gradle/current
ENV PATH="/usr/local/bin:$JAVA_HOME/bin:$MAVEN_HOME/bin:$GRADLE_HOME/bin:$PATH"
EXPOSE 8080

CMD ["tail", "-f", "/dev/null"]