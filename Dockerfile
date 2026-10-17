FROM zaproxy/zap-stable:latest
USER root

RUN apt-get update && apt-get install -y \
    nmap \
    perl \
    libnet-ssleay-perl \
    git \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/sullo/nikto /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt
COPY . .
RUN chmod +x entrypoint.sh
ENTRYPOINT ["./entrypoint.sh"]
