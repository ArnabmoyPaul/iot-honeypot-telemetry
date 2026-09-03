# Troubleshooting Guide

## Common Issues

### Issue: Elasticsearch fails to start with "max virtual memory areas" error

**Cause:** vm.max_map_count too low on host  
**Fix:**
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Issue: Cowrie container exits immediately

**Check:**
```bash
docker logs cowrie
```

**Common causes:**
- Port 2222 already in use: `sudo lsof -i :2222`
- Permission issues: `sudo chown -R 1000:1000 data/cowrie-logs`
- Missing config: Verify `honeypots/cowrie/cowrie.cfg` exists

### Issue: No logs appearing in Kibana

**Debug chain:**
1. Check honeypot is generating logs: `ls -la data/cowrie-logs/`
2. Check Filebeat is reading: `docker logs filebeat`
3. Check Logstash parsing: `docker logs logstash`
4. Check Elasticsearch indices: `curl -u elastic:password localhost:9200/_cat/indices`
5. Check Kibana connection: `docker logs kibana`

### Issue: GeoIP data missing (all locations show "N/A")

**Fix:**
```bash
# Verify GeoIP database exists
ls -la data/geoip/GeoLite2-City.mmdb

# If missing, download from MaxMind (requires free account)
# Place file in data/geoip/ and restart Logstash
make down && make up
```

### Issue: iptables rules blocking legitimate traffic

**Emergency reset:**
```bash
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

**Then re-apply rules carefully:**
```bash
sudo bash firewall/iptables-rules.sh
```

### Issue: Deception score shows 0.0

**Check:**
```bash
python3 scripts/deception-score.py
```

**Common causes:**
- Cowrie config file not found at expected path
- userdb.txt contains fake accounts (phil, richard)
- Filesystem path incorrect in scorer

### Issue: High memory usage / OOM kills

**For t2.micro (1GB RAM):**
- Do NOT run full ELK stack
- Use external log aggregation (Grafana Cloud free tier)
- Or reduce Elasticsearch heap: `ES_JAVA_OPTS=-Xms512m -Xmx512m`

### Issue: AWS abuse complaint received

**Immediate actions:**
1. `make down` to stop all services
2. Check `/var/log/kern.log` for abuse block logs
3. Verify iptables rules were applied
4. If containment failed, review `firewall/iptables-rules.sh`
5. Contact AWS abuse team with containment evidence

## Getting Help

- Cowrie issues: [Cowrie GitHub](https://github.com/cowrie/cowrie)
- Dionaea issues: [Dionaea GitHub](https://github.com/DinoTools/dionaea)
- ELK issues: [Elastic Discuss](https://discuss.elastic.co/)
- General: Open issue in this repository
