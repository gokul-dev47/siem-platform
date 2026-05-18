"""SIEM Log Generator v5.0 — uses host.docker.internal"""
import os,json,time,random,logging
from datetime import datetime
import redis,requests

logging.basicConfig(level=logging.INFO,format="%(asctime)s [LOGGEN] %(message)s")
logger=logging.getLogger("loggen")

ES  =os.getenv("ELASTICSEARCH_HOST","http://host.docker.internal:9200")
RH  =os.getenv("REDIS_HOST","host.docker.internal")
INT =int(os.getenv("GENERATE_INTERVAL","8"))

IPS=["103.45.67.89","185.234.21.4","91.108.4.16","212.71.235.44",
     "5.188.206.29","194.165.16.78","45.142.212.100","89.248.167.131"]
SQLI=["' OR 1=1 --","' UNION SELECT * FROM users--","'; DROP TABLE users;--"]
XSS=["<script>alert('XSS')</script>","<img src=x onerror=alert(1)>"]
LFI=["../../../etc/passwd","../../../../etc/shadow"]
RCE=["; cat /etc/passwd","| whoami","`id`"]
UAS=["sqlmap/1.7.8","Nikto/2.1.6","Nmap Scripting Engine","masscan/1.0"]

_r=None
def get_r():
    global _r
    try:
        if _r is None:
            _r=redis.Redis(host=RH,port=6379,decode_responses=True,
                socket_timeout=2,socket_connect_timeout=2)
        _r.ping(); return _r
    except Exception:
        _r=None; return None

def ingest(e):
    try: requests.post(f"{ES}/siem-logs-{datetime.utcnow().strftime('%Y.%m.%d')}/_doc",
            json=e,headers={"Content-Type":"application/json"},timeout=3)
    except Exception: pass

def inc(rid,win=60):
    r=get_r()
    if not r: return
    k=f"siem:counter:{rid}"
    try: p=r.pipeline();p.incr(k);p.expire(k,win);p.execute()
    except Exception: pass

def ev(etype,sev,ip,msg,port=80,proto="TCP",tags=None):
    ts=datetime.utcnow()
    return {"@timestamp":ts.isoformat()+"Z","event_type":etype,"severity":sev,
            "source_ip":ip,"message":msg,"log_source":"siem-generator",
            "dest_ip":"10.0.0.1","dest_port":port,"protocol":proto,
            "tags":tags or [],"raw_log":f"[{ts.isoformat()}] {etype} {ip}"}

def ssh():
    ip=random.choice(IPS);n=random.randint(8,20)
    evts=[ev("AUTH_FAILURE","critical",ip,"SSH brute force failed auth",port=22,tags=["ssh"]) for _ in range(n)]
    inc("SSH_BRUTE_FORCE",60);logger.info(f"SSH brute {ip} ({n}x)");return evts

def scan():
    ip=random.choice(IPS);ports=random.sample(range(1,65535),random.randint(20,50))
    evts=[ev("PORT_SCAN","high",ip,f"SYN scan port {p}",port=p,tags=["scan"]) for p in ports]
    inc("PORT_SCAN",30);logger.info(f"Port scan {ip} ({len(ports)} ports)");return evts

def sqli():
    ip=random.choice(IPS);inc("SQL_INJECTION",60);logger.info(f"SQLi {ip}")
    return [ev("SQL_INJECTION","high",ip,"SQLi attempt",port=443,proto="HTTPS",tags=["sqli"])]

def xss():
    ip=random.choice(IPS);inc("XSS_ATTEMPT",60);logger.info(f"XSS {ip}")
    return [ev("XSS_ATTEMPT","medium",ip,"XSS payload",port=443,proto="HTTPS",tags=["xss"])]

def lfi():
    ip=random.choice(IPS);inc("DIR_TRAVERSAL",60);logger.info(f"LFI {ip}")
    return [ev("DIR_TRAVERSAL","medium",ip,"Dir traversal attempt",port=80,tags=["lfi"])]

def rce():
    ip=random.choice(IPS);inc("RCE_ATTEMPT",60);logger.info(f"RCE {ip}")
    return [ev("RCE_ATTEMPT","critical",ip,"RCE attempt",port=8080,tags=["rce"])]

def sua():
    ip=random.choice(IPS);ua=random.choice(UAS);inc("SUSPICIOUS_UA",60)
    return [ev("SUSPICIOUS_UA","medium",ip,f"Malicious UA: {ua}",tags=["scanner"])]

def normal():
    ip=f"192.168.{random.randint(0,5)}.{random.randint(1,50)}"
    return [ev("HTTP_REQUEST","info",ip,"Normal HTTP request",tags=["normal"])]

def run():
    logger.info(f"Log Generator v5.0 — ES:{ES} Redis:{RH}")
    for i in range(40):
        try:
            if requests.get(f"{ES}/_cluster/health",timeout=5).status_code==200:
                logger.info("ES ready"); break
        except Exception: pass
        logger.info(f"Waiting ES... ({i+1}/40)"); time.sleep(10)
    try:
        requests.put(f"{ES}/_index_template/siem-logs",json={
            "index_patterns":["siem-logs-*"],
            "template":{"settings":{"number_of_shards":1,"number_of_replicas":0},
                "mappings":{"properties":{"@timestamp":{"type":"date"},
                    "event_type":{"type":"keyword"},"severity":{"type":"keyword"},
                    "source_ip":{"type":"ip"},"dest_port":{"type":"integer"},
                    "message":{"type":"text"},"protocol":{"type":"keyword"},
                    "tags":{"type":"keyword"},"raw_log":{"type":"text"}}}}},timeout=5)
        logger.info("Index template OK")
    except Exception as e: logger.warning(f"Template: {e}")
    pool=[ssh]*4+[scan]*6+[sqli]*8+[xss]*6+[lfi]*5+[rce]*2+[sua]*5+[normal]*64
    b=0
    while True:
        try:
            b+=1;picks=list(set(random.sample(pool,min(8,len(pool)))));tot=0
            for fn in picks:
                for e in fn(): ingest(e);tot+=1
            logger.info(f"Batch #{b}: {tot} events")
        except Exception as e: logger.error(f"Batch: {e}")
        time.sleep(INT)

if __name__=="__main__": run()
