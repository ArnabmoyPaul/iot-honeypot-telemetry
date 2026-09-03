FROM cowrie/cowrie:latest

# Switch to root for configuration
USER root

# Install additional tools for IoT realism
RUN apt-get update && apt-get install -y --no-install-recommends     busybox-static     && rm -rf /var/lib/apt/lists/*

# Copy custom configuration
COPY cowrie.cfg /cowrie/cowrie-git/etc/cowrie.cfg
COPY userdb.txt /cowrie/cowrie-git/etc/userdb.txt
COPY scripts/banner-mod.py /cowrie/cowrie-git/bin/banner-mod.py

# Ensure proper permissions
RUN chown -R cowrie:cowrie /cowrie/cowrie-git/etc /cowrie/cowrie-git/bin

# Create realistic IoT filesystem structure
RUN mkdir -p /cowrie/cowrie-git/share/cowrie/fs.pickle     && chown cowrie:cowrie /cowrie/cowrie-git/share/cowrie/fs.pickle

# Add artificial latency wrapper to simulate embedded CPU
RUN echo '#!/bin/bash
exec nice -n 19 ionice -c 3 /cowrie/cowrie-env/bin/python3 /cowrie/cowrie-git/src/cowrie/\$@'     > /usr/local/bin/cowrie-latency && chmod +x /usr/local/bin/cowrie-latency

# Switch back to cowrie user
USER cowrie

# Expose SSH and Telnet ports
EXPOSE 2222 2223

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3     CMD echo "SSH-2.0-test" | nc -w 2 localhost 2222 | grep -q "dropbear" || exit 1

CMD ["/cowrie/cowrie-env/bin/python3", "-m", "cowrie", "start"]
