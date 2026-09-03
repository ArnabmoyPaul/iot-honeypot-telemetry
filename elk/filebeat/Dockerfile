FROM docker.elastic.co/beats/filebeat:8.11.0

# Copy configuration
COPY filebeat.yml /usr/share/filebeat/filebeat.yml

USER root
RUN chown root:filebeat /usr/share/filebeat/filebeat.yml
RUN chmod go-w /usr/share/filebeat/filebeat.yml
USER filebeat

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3     CMD filebeat test output || exit 1
