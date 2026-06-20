# doublethink Android dev container - build-only (no emulator by default).
# Toolchains live here, never on the host. Builds APKs + runs unit tests.
#
# Pinned toolchain (matches the host android project's known-good matrix):
#   - Temurin 21 JDK (current LTS, satisfies AGP's JDK >=17 floor)
#   - cmdline-tools (Linux): build 14742923
#   - compileSdk 36 / build-tools 36.0.0
#   - Gradle 8.13
#
# No Firebase, Node, FCM, Google Play Services, or python-pil: this app is pure AOSP.
FROM eclipse-temurin:21-jdk-jammy@sha256:801b7e1a9c4befaf82bf9a2a58025ef43a7694bbc84779187ad0524d84742772

# --- Base utilities (git/unzip/curl needed for SDK install + builds) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Gradle (pinned; used to generate the project's wrapper, then the wrapper is used) ---
ARG GRADLE_VERSION=8.13
RUN curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -o /tmp/gradle.zip \
    && unzip -q /tmp/gradle.zip -d /opt \
    && ln -s /opt/gradle-${GRADLE_VERSION}/bin/gradle /usr/local/bin/gradle \
    && rm /tmp/gradle.zip

# --- Android SDK command-line tools ---
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=${ANDROID_SDK_ROOT}
ENV PATH=${PATH}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools

ARG CMDLINE_TOOLS_ZIP=commandlinetools-linux-14742923_latest.zip
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools \
    && curl -fsSL "https://dl.google.com/android/repository/${CMDLINE_TOOLS_ZIP}" -o /tmp/cmdline-tools.zip \
    && unzip -q /tmp/cmdline-tools.zip -d /tmp/cmdline-tools \
    # Google ships the tools under a top-level "cmdline-tools/"; they must live under ".../latest/"
    && mv /tmp/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest \
    && rm -rf /tmp/cmdline-tools /tmp/cmdline-tools.zip

# --- Accept licenses + install required SDK packages ---
RUN yes | sdkmanager --licenses >/dev/null \
    && sdkmanager --install \
        "platform-tools" \
        "platforms;android-36" \
        "build-tools;36.0.0"

# Non-root user so files written to mounted volumes are owned by the host user.
# UID/GID overridden at build time to match the host (see compose).
ARG HOST_UID=1000
ARG HOST_GID=1000
RUN groupadd -g ${HOST_GID} dev 2>/dev/null || true \
    && useradd -m -u ${HOST_UID} -g ${HOST_GID} -s /bin/bash dev 2>/dev/null || true \
    && chown -R ${HOST_UID}:${HOST_GID} ${ANDROID_SDK_ROOT}

USER dev
WORKDIR /workspace

# Gradle cache persists via the mounted volume (see compose).
ENV GRADLE_USER_HOME=/home/dev/.gradle

CMD ["/bin/bash"]
