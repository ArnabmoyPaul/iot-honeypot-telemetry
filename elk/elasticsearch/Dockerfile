FROM docker.elastic.co/elasticsearch/elasticsearch:8.11.0

# Copy custom configuration
COPY elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml

# Install analysis plugins for IoT log text processing
RUN bin/elasticsearch-plugin install analysis-icu || true

EXPOSE 9200 9300
