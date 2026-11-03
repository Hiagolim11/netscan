# netscan — servidor web para varrer a rede local a partir de um servidor (Umbrel, NAS, mini PC).
# Precisa rodar com a rede do host (network_mode: host) para enxergar a LAN.
FROM kalilinux/kali-rolling

# exploitdb (~500 MB) dá a busca de exploits públicos por serviço; desligue com --build-arg WITH_EXPLOITDB=false
ARG WITH_EXPLOITDB=true

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap python3 iproute2 ca-certificates tzdata \
 && if [ "$WITH_EXPLOITDB" = "true" ]; then apt-get install -y --no-install-recommends exploitdb; fi \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY netscan.py analysis.py automation.py server.py ./
COPY renderer/ ./renderer/

# HOME no volume: o cache do CISA KEV/EPSS sobrevive a atualizações do container
ENV NETSCAN_DATA=/data \
    HOME=/data \
    NETSCAN_PORT=7765 \
    PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 7765

HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python3 -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/login.html' % os.environ.get('NETSCAN_PORT','7765'), timeout=4)" || exit 1

ENTRYPOINT ["python3", "/app/server.py"]
