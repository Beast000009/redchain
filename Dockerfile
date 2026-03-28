# ─── RedChain Dockerfile ────────────────────────────────────────────────────
# Multi-stage build: installs all system tools + Python deps
# Usage:
#   docker build -t redchain .
#   docker run --rm -it --env-file .env redchain scan -t target.com --no-scope-check
# ────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

# Prevent dpkg from asking configuration questions
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ── System dependencies ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core tools
    nmap \
    git \
    curl \
    wget \
    dnsutils \
    whois \
    # Build helpers for Python packages (WeasyPrint/Pango)
    gcc \
    g++ \
    libffi-dev \
    libpango1.0-dev \
    libcairo2-dev \
    libgdk-pixbuf-xlib-2.0-dev \
    # Networking and DNS
    iputils-ping \
    net-tools \
    # Ruby for whatweb
    ruby \
    ruby-dev \
    # Perl for nikto
    perl \
    libnet-ssleay-perl \
    # Go for gobuster/cvemap/subfinder
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# ── Install Nikto from source (not in Debian Trixie apt) ─────────────────────
RUN git clone https://github.com/sullo/nikto.git /opt/nikto 2>/dev/null || true && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl 2>/dev/null || true

# ── Install WhatWeb from gem ──────────────────────────────────────────────────
RUN gem install whatweb 2>/dev/null || true

# ── Install Go-based tools ────────────────────────────────────────────────────
ENV GOPATH=/root/go
ENV PATH="$GOPATH/bin:$PATH"

RUN go install github.com/OJ/gobuster/v3@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true

# ── Install Python networking tools ─────────────────────────────────────────
RUN pip install --no-cache-dir theHarvester wafw00f paramiko 2>/dev/null || true

# ── Update nuclei templates ───────────────────────────────────────────────────
RUN nuclei -update-templates -silent 2>/dev/null || true

# ── Install SecLists wordlists (minimal subset) ──────────────────────────────
RUN mkdir -p /usr/share/wordlists/seclists/Discovery/Web-Content && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt 2>/dev/null || true

# ── Python app ────────────────────────────────────────────────────────────────
WORKDIR /app

# Copy application code
COPY . .

# Install RedChain as a system command (includes all dependencies)
RUN pip install --no-cache-dir .

# Create reports output directory
RUN mkdir -p /app/reports

# ── Entrypoint ────────────────────────────────────────────────────────────────
ENTRYPOINT ["redchain"]
CMD ["--help"]
