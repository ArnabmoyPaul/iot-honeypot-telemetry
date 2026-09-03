FROM docker.elastic.co/logstash/logstash:8.11.0

# Install GeoIP filter plugin (bundled, but ensure latest)
RUN bin/logstash-plugin install --no-verify logstash-filter-geoip || true

# Copy pipeline configurations
COPY pipeline/ /usr/share/logstash/pipeline/
COPY patterns/ /usr/share/logstash/patterns/

# Ensure proper permissions
USER root
RUN chown -R logstash:logstash /usr/share/logstash/pipeline /usr/share/logstash/patterns
USER logstash

EXPOSE 5044

CMD ["logstash", "-f", "/usr/share/logstash/pipeline/"]
