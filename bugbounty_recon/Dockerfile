FROM ubuntu:22.04

LABEL maintainer="rootzro"
LABEL description="Bug Bounty Recon - Docker Container with all tools pre-installed"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    curl \
    wget \
    unzip \
    nmap \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Install Python dependencies
RUN pip3 install requests colorama


# Install Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 

# Install wafw00f
RUN pip3 install wafw00f

# Update nuclei templates
RUN nuclei -update-templates

# Create working directory
WORKDIR /data

# Copy Python script
COPY bugbounty_recon.py /usr/local/bin/bugbounty_recon.py
COPY modules/ /usr/local/bin/modules/
RUN chmod +x /usr/local/bin/bugbounty_recon.py

# Create directory structure
RUN mkdir -p /data/config /data/output

# Set entrypoint
ENTRYPOINT ["python3", "/usr/local/bin/bugbounty_recon.py"]