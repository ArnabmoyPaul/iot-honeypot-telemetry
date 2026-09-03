FROM docker.elastic.co/kibana/kibana:8.11.0

# Copy pre-built dashboards
COPY dashboards/ /usr/share/kibana/dashboards/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5     CMD curl -f -s http://localhost:5601/api/status | grep -q '"state":"green"' || exit 1

EXPOSE 5601
