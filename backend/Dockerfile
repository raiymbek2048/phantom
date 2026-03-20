# Stage 1: Build Go security tools
FROM golang:1.24-bookworm AS go-builder

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# Stage 2: Final image
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    nmap \
    whois \
    dnsutils \
    chromium \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    libcairo2 \
    default-jre-headless \
    unzip \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Install jadx (APK decompiler)
RUN curl -sL https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip -o /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    chmod +x /opt/jadx/bin/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm /tmp/jadx.zip

# Install apktool
RUN curl -sL https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /usr/local/bin/apktool && \
    curl -sL https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.10.0.jar -o /usr/local/bin/apktool.jar && \
    chmod +x /usr/local/bin/apktool

# Copy Go tools from builder
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/gohttpx
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/
COPY --from=go-builder /go/bin/assetfinder /usr/local/bin/
COPY --from=go-builder /go/bin/gau /usr/local/bin/

# Install wafw00f
RUN pip install --no-cache-dir wafw00f

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium && \
    playwright install-deps chromium

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
