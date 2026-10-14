FROM zaproxy/zap-stable

USER root
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-yaml \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the local patched package and requirements
COPY python-owasp-zap-v2-0.0.9 /app/python-owasp-zap-v2-0.0.9
COPY requirements.txt .

# Install dependencies without build isolation
RUN pip3 install --no-cache-dir --no-build-isolation -e ./python-owasp-zap-v2-0.0.9 --break-system-packages
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

COPY . /app

RUN chmod +x run_scan.py
