FROM dinotools/dionaea:latest

USER root

# Install additional protocol handlers for IoT emulation
RUN apt-get update && apt-get install -y --no-install-recommends     libmqtt0     && rm -rf /var/lib/apt/lists/*

# Copy custom configuration
COPY dionaea.cfg /opt/dionaea/etc/dionaea/dionaea.cfg
COPY services/mqtt.py /opt/dionaea/lib/dionaea/python/dionaea/mqtt/

# Create directories for captured payloads
RUN mkdir -p /opt/dionaea/var/dionaea/bistreams     /opt/dionaea/var/dionaea/log     /opt/dionaea/var/dionaea/binaries     && chown -R dionaea:dionaea /opt/dionaea/var

# Ensure proper permissions
RUN chown -R dionaea:dionaea /opt/dionaea/etc /opt/dionaea/lib

USER dionaea

# Expose IoT-relevant ports
EXPOSE 445 21 80 3306 1883

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3     CMD nc -z localhost 1883 || exit 1

CMD ["dionaea", "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg"]
