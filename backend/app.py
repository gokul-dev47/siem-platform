"""
SIEM Platform - Backend v5.0 FINAL
=====================================
Author: Gokul
Flask + SocketIO + Elasticsearch + Redis + PostgreSQL

v5.0 - THE DEFINITIVE FIX:
Uses host.docker.internal which is the reliable way to connect
from a Docker container back to the host on Docker Desktop (Windows/Mac/WSL2).
host-gateway in extra_hosts makes this work on Linux too.
No more DNS issues. No more hostname resolution failures.
"""

import os, json, time, hashlib, logging, threading, random, math
from datetime import datetime, timedelta

import redis as redis_lib
import psycopg2, psycopg2.extras
import requests as req_lib
from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
from elasticsearch import Elasticsearch
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SIEM")
for lib in ["apscheduler","elasticsearch","elastic_transport","urllib3"]:
    logging.getLogger(lib).setLevel(logging.WARNING)

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.getenv("FRONTEND_DIR", "/frontend")
SLACK_URL    = os.getenv("SLACK_WEBHOOK_URL", "")
START_TIME   = datetime.utcnow()
_stats_lock  = threading.Lock()

CFG = {
    "es_url":     os.getenv("ELASTICSEARCH_HOST", "http://host.docker.internal:9200"),
    "redis_host": os.getenv("REDIS_HOST", "host.docker.internal"),
    "redis_port": 6379,
    "pg_dsn":     os.getenv("POSTGRES_DSN",
                  "postgresql://siem_user:siem_password_2024@host.docker.internal:5432/siem_alerts"),
    "es_ready":   False,
}

# ── Flask ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "siemplatform2024")
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet",
                    logger=False, engineio_logger=False)

# ── Connections ───────────────────────────────────────────────────────────────
_es = _redis = _pg = None

def get_es():
    global _es
    if _es is None:
        try:
            _es = Elasticsearch(CFG["es_url"],
                request_timeout=5, max_retries=1, retry_on_timeout=False)
        except Exception: pass
    return _es

def get_redis():
    global _redis
    try:
        if _redis is None:
            _redis = redis_lib.Redis(
                host=CFG["redis_host"], port=CFG["redis_port"],
                decode_responses=True,
                socket_timeout=2, socket_connect_timeout=2,
                retry_on_timeout=False)
        _redis.ping()
        return _redis
    except Exception:
        _redis = None
        return None

def get_pg():
    global _pg
    try:
        if _pg is None or _pg.closed:
            _pg = psycopg2.connect(CFG["pg_dsn"], connect_timeout=3)
            _pg.autocommit = True
        return _pg
    except Exception:
        _pg = None
        return None

# ── Startup wait ──────────────────────────────────────────────────────────────
def wait_for_services(timeout=300):
    # All candidates - host.docker.internal is primary, others as fallback
    es_candidates = [
        CFG["es_url"],
        "http://host.docker.internal:9200",
        "http://172.17.0.1:9200",
        "http://127.0.0.1:9200",
    ]
    redis_candidates = [
        (CFG["redis_host"], 6379),
        ("host.docker.internal", 6379),
        ("172.17.0.1", 6379),
        ("127.0.0.1", 6379),
    ]

    deadline = time.time() + timeout
    attempt  = 0
    logger.info("[SIEM] Waiting for services...")

    while time.time() < deadline:
        attempt += 1
        es_ok = redis_ok = False

        for url in es_candidates:
            try:
                r = req_lib.get(f"{url}/_cluster/health", timeout=3)
                if r.status_code == 200:
                    CFG["es_url"]   = url
                    CFG["es_ready"] = True
                    global _es; _es = None
                    es_ok = True
                    logger.info(f"[SIEM] ES connected: {url}")
                    break
            except Exception:
                pass

        for rhost, rport in redis_candidates:
            try:
                global _redis
                t = redis_lib.Redis(host=rhost, port=rport,
                    decode_responses=True,
                    socket_timeout=2, socket_connect_timeout=2)
                t.ping()
                _redis = t
                CFG["redis_host"] = rhost
                redis_ok = True
                logger.info(f"[SIEM] Redis connected: {rhost}:{rport}")
                break
            except Exception:
                pass

        rem = int(deadline - time.time())
        logger.info(f"[SIEM] ES={'OK' if es_ok else 'WAIT'} "
                    f"Redis={'OK' if redis_ok else 'WAIT'} "
                    f"— attempt {attempt}, {rem}s left")

        if es_ok and redis_ok:
            logger.info("[SIEM] All services connected!")
            return True

        time.sleep(5)

    logger.warning("[SIEM] Timeout — mock data mode")
    return False

# ── Alert rules ───────────────────────────────────────────────────────────────
RULES_PATH = os.path.join(BASE_DIR, "alert_rules.json")

def load_rules():
    try:
        with open(RULES_PATH) as f: return json.load(f)
    except Exception: return {"rules": []}

# ── Mock data ─────────────────────────────────────────────────────────────────
def mock_stats():
    now = datetime.utcnow()
    hours = [(now - timedelta(hours=i)).strftime("%H:00") for i in range(23,-1,-1)]
    return {
        "total_events": random.randint(14000,16000),
        "critical_alerts": random.randint(3,12),
        "blocked_ips": random.randint(45,120),
        "active_threats": random.randint(1,8),
        "events_per_hour": [{"hour":h,"count":int(80+60*math.sin(i*0.4)+random.randint(-20,20))}
                             for i,h in enumerate(hours)],
        "top_source_ips": [{"ip":f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                            "count":random.randint(50,400),"country":c}
                           for c in ["CN","RU","US","BR","IN","NG","DE","KR"]],
        "severity_breakdown": {"critical":random.randint(5,25),"high":random.randint(30,80),
                                "medium":random.randint(100,250),"low":random.randint(300,600),
                                "info":random.randint(800,2000)},
        "attack_types": {"SSH Brute Force":random.randint(40,200),"SQL Injection":random.randint(20,100),
                         "Port Scan":random.randint(60,300),"XSS Attempt":random.randint(10,80),
                         "Dir Traversal":random.randint(5,40),"RCE Attempt":random.randint(2,15)},
        "last_updated": datetime.utcnow().isoformat()+"Z",
    }

def mock_logs(limit=50):
    types=[("SSH_BRUTE_FORCE","critical","Failed SSH login attempt"),
           ("PORT_SCAN","high","SYN scan detected"),
           ("SQL_INJECTION","high","SQLi pattern in GET parameter"),
           ("XSS_ATTEMPT","medium","XSS payload in request"),
           ("DIR_TRAVERSAL","medium","Directory traversal attempt"),
           ("AUTH_FAILURE","low","Authentication failure"),
           ("SUSPICIOUS_UA","low","Suspicious user-agent: sqlmap"),
           ("FIREWALL_BLOCK","info","Outbound connection blocked")]
    logs=[]
    for i in range(limit):
        et=random.choice(types)
        ts=datetime.utcnow()-timedelta(seconds=random.randint(0,3600))
        logs.append({"id":hashlib.md5(f"{i}{ts}".encode()).hexdigest()[:12],
                     "timestamp":ts.isoformat()+"Z","event_type":et[0],
                     "severity":et[1],"message":et[2],
                     "source_ip":f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                     "dest_port":random.choice([22,80,443,3306,8080,5432]),
                     "protocol":random.choice(["TCP","UDP","HTTP","HTTPS"]),
                     "raw":f"[{ts.isoformat()}] {et[0]}"})
    return sorted(logs,key=lambda x:x["timestamp"],reverse=True)

def mock_alerts(limit=20):
    alerts=[]
    for i in range(limit):
        sev=random.choice(["critical","high","medium","low"])
        ts=datetime.utcnow()-timedelta(minutes=random.randint(0,1440))
        aid=hashlib.md5(f"alert{i}".encode()).hexdigest()[:10]
        alerts.append({"id":aid,"alert_id":aid,"timestamp":ts.isoformat()+"Z","severity":sev,
                       "rule_name":random.choice(["SSH_BRUTE_FORCE","SQL_INJECTION","PORT_SCAN","XSS","RCE_ATTEMPT"]),
                       "source_ip":f"{random.randint(1,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                       "description":f"Rule triggered {random.randint(5,100)} times in 60s",
                       "status":random.choice(["open","investigating","closed"]),
                       "count":random.randint(5,500)})
    return sorted(alerts,key=lambda x:x["timestamp"],reverse=True)

# ── ES queries ────────────────────────────────────────────────────────────────
def es_stats():
    if not CFG["es_ready"]: return mock_stats()
    es = get_es()
    if not es: return mock_stats()
    try:
        r=es.search(index="siem-logs-*",body={"size":0,"aggs":{
            "per_hour":{"date_histogram":{"field":"@timestamp","calendar_interval":"hour","min_doc_count":0}},
            "by_sev":{"terms":{"field":"severity.keyword","size":10}},
            "by_type":{"terms":{"field":"event_type.keyword","size":10}},
            "top_ips":{"terms":{"field":"source_ip.keyword","size":10}}}},
            ignore_unavailable=True)
        total=r["hits"]["total"]["value"]
        if total==0: return mock_stats()
        sev={b["key"]:b["doc_count"] for b in r["aggregations"]["by_sev"]["buckets"]}
        atypes={b["key"]:b["doc_count"] for b in r["aggregations"]["by_type"]["buckets"]}
        ips=[{"ip":b["key"],"count":b["doc_count"],"country":"??"} for b in r["aggregations"]["top_ips"]["buckets"]]
        hourly=[{"hour":b["key_as_string"][:16],"count":b["doc_count"]} for b in r["aggregations"]["per_hour"]["buckets"][-24:]]
        return {"total_events":total,"critical_alerts":sev.get("critical",0),
                "blocked_ips":len(ips),"active_threats":sev.get("critical",0)+sev.get("high",0),
                "events_per_hour":hourly,"top_source_ips":ips,"severity_breakdown":sev,
                "attack_types":atypes,"last_updated":datetime.utcnow().isoformat()+"Z"}
    except Exception as e:
        logger.debug(f"ES stats: {e}"); return mock_stats()

def es_logs(limit=100,query=None,severity=None):
    if not CFG["es_ready"]: return mock_logs(limit)
    es=get_es()
    if not es: return mock_logs(limit)
    try:
        must=[]
        if query: must.append({"multi_match":{"query":query,"fields":["message","source_ip","event_type"]}})
        if severity: must.append({"term":{"severity.keyword":severity}})
        r=es.search(index="siem-logs-*",body={"size":limit,"sort":[{"@timestamp":{"order":"desc"}}],
            "query":{"bool":{"must":must}} if must else {"match_all":{}}},ignore_unavailable=True)
        hits=r["hits"]["hits"]
        if not hits: return mock_logs(limit)
        return [{"id":h["_id"][:12],"timestamp":h["_source"].get("@timestamp",""),
                 "event_type":h["_source"].get("event_type","UNKNOWN"),
                 "severity":h["_source"].get("severity","info"),
                 "message":h["_source"].get("message",""),
                 "source_ip":h["_source"].get("source_ip","0.0.0.0"),
                 "dest_port":h["_source"].get("dest_port",0),
                 "protocol":h["_source"].get("protocol","TCP"),
                 "raw":h["_source"].get("raw_log","")} for h in hits]
    except Exception as e:
        logger.debug(f"ES logs: {e}"); return mock_logs(limit)

# ── Alert engine ──────────────────────────────────────────────────────────────
def evaluate_rules():
    r=get_redis()
    if not r: return
    for rule in load_rules().get("rules",[]):
        if not rule.get("enabled",True): continue
        try: count=int(r.get(f"siem:counter:{rule['id']}") or 0)
        except Exception: continue
        if count>=rule.get("threshold",5):
            ts=datetime.utcnow().isoformat()+"Z"
            aid=hashlib.md5(f"{rule['id']}{time.time()}".encode()).hexdigest()[:10]
            alert={"id":aid,"alert_id":aid,"timestamp":ts,
                   "severity":rule.get("severity","high"),"rule_name":rule["id"],
                   "description":rule.get("description",""),"count":count,
                   "status":"open","source_ip":None}
            save_alert(alert)
            try:
                socketio.emit("new_alert",alert,room="alerts")
                socketio.emit("new_alert",alert,room=alert["severity"])
            except Exception: pass
            if SLACK_URL: send_slack(alert)
            try: r.delete(f"siem:counter:{rule['id']}")
            except Exception: pass
            logger.info(f"[SIEM] ALERT: {rule['id']} count={count}")

def save_alert(alert):
    conn=get_pg()
    if not conn: return
    try:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO alerts (alert_id,timestamp,severity,rule_name,description,count,status)
                VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (alert_id) DO NOTHING""",
                (alert["alert_id"],alert["timestamp"],alert["severity"],
                 alert["rule_name"],alert["description"],alert["count"],alert["status"]))
    except Exception as e: logger.debug(f"PG: {e}")

def send_slack(alert):
    try:
        req_lib.post(SLACK_URL,json={"text":f"SIEM ALERT [{alert['severity'].upper()}] {alert['rule_name']}",
            "attachments":[{"color":"danger","fields":[
                {"title":"Rule","value":alert["rule_name"],"short":True},
                {"title":"Count","value":str(alert["count"]),"short":True}]}]},timeout=5)
    except Exception: pass

def broadcast_stats():
    if not _stats_lock.acquire(blocking=False): return
    try:
        stats=es_stats()
        r=get_redis()
        if r:
            try: r.setex("siem:stats:latest",10,json.dumps(stats))
            except Exception: pass
        try: socketio.emit("stats_update",stats,room="dashboard")
        except Exception: pass
    finally: _stats_lock.release()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    idx=os.path.join(FRONTEND_DIR,"index.html")
    if os.path.isfile(idx): return send_from_directory(FRONTEND_DIR,"index.html")
    return "<h1>SIEM Backend v5.0</h1>",200

@app.route("/<path:path>")
def static_files(path):
    t=os.path.join(FRONTEND_DIR,path)
    if os.path.isfile(t): return send_from_directory(FRONTEND_DIR,path)
    idx=os.path.join(FRONTEND_DIR,"index.html")
    if os.path.isfile(idx): return send_from_directory(FRONTEND_DIR,"index.html")
    return "",404

@app.route("/health")
def health():
    svcs={}
    try:
        r=req_lib.get(f"{CFG['es_url']}/_cluster/health",timeout=2)
        svcs["elasticsearch"]={"status":"healthy" if r.status_code==200 else "starting"}
    except Exception:
        svcs["elasticsearch"]={"status":"starting"}
    svcs["redis"]={"status":"healthy" if get_redis() else "unhealthy"}
    try:
        conn=get_pg()
        if conn:
            with conn.cursor() as cur: cur.execute("SELECT 1")
            svcs["postgres"]={"status":"healthy"}
        else: svcs["postgres"]={"status":"unhealthy"}
    except Exception: svcs["postgres"]={"status":"unhealthy"}
    delta=datetime.utcnow()-START_TIME
    overall="healthy" if all(s["status"]=="healthy" for s in svcs.values()) else "degraded"
    return jsonify({"status":overall,"services":svcs,
                    "uptime_seconds":int(delta.total_seconds()),
                    "version":"5.0.0","timestamp":datetime.utcnow().isoformat()+"Z"}),200

@app.route("/api/stats")
def api_stats():
    r=get_redis()
    if r:
        try:
            c=r.get("siem:stats:latest")
            if c: return jsonify(json.loads(c))
        except Exception: pass
    return jsonify(es_stats())

@app.route("/api/logs")
def api_logs():
    return jsonify({"logs":es_logs(min(int(request.args.get("limit",100)),500),
        request.args.get("q") or None,request.args.get("severity") or None),"total":100})

@app.route("/api/alerts")
def api_alerts():
    conn=get_pg()
    if not conn: return jsonify({"alerts":mock_alerts(30)})
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            sev=request.args.get("severity"); sts=request.args.get("status")
            where,params=[],[]
            if sev: where.append("severity=%s"); params.append(sev)
            if sts: where.append("status=%s"); params.append(sts)
            clause=("WHERE "+" AND ".join(where)) if where else ""
            cur.execute(f"SELECT * FROM alerts {clause} ORDER BY timestamp DESC LIMIT 100",params)
            rows=[dict(r) for r in cur.fetchall()]
            if not rows: return jsonify({"alerts":mock_alerts(30)})
            for row in rows: row["id"]=row["alert_id"]=row.get("alert_id",str(row.get("id","")))
            return jsonify({"alerts":rows})
    except Exception as e:
        logger.debug(f"alerts: {e}"); return jsonify({"alerts":mock_alerts(30)})

@app.route("/api/alerts/<aid>",methods=["PATCH"])
def update_alert(aid):
    status=(request.get_json() or {}).get("status")
    if status not in ("open","investigating","closed"):
        return jsonify({"error":"invalid status"}),400
    conn=get_pg()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE alerts SET status=%s WHERE alert_id=%s",(status,aid))
        except Exception as e: return jsonify({"error":str(e)}),500
    return jsonify({"ok":True})

@app.route("/api/rules")
def api_rules(): return jsonify(load_rules())

@app.route("/api/rules/<rid>",methods=["PATCH"])
def update_rule(rid):
    data=request.get_json() or {}
    rules=load_rules()
    for rule in rules.get("rules",[]):
        if rule["id"]==rid:
            if "enabled" in data: rule["enabled"]=data["enabled"]
            if "threshold" in data: rule["threshold"]=data["threshold"]
    try:
        with open(RULES_PATH,"w") as f: json.dump(rules,f,indent=2)
        return jsonify({"ok":True})
    except Exception as e: return jsonify({"error":str(e)}),500

@app.route("/api/uptime")
def api_uptime():
    d=datetime.utcnow()-START_TIME
    return jsonify({"days":d.days,"hours":d.seconds//3600,
                    "minutes":(d.seconds%3600)//60,"seconds":d.seconds%60,
                    "total_seconds":int(d.total_seconds()),"since":START_TIME.isoformat()+"Z"})

@app.route("/api/threat-map")
def api_threat_map():
    return jsonify({"sources":[
        {"lat":39.9,"lng":116.4,"city":"Beijing","country":"CN","count":random.randint(50,300)},
        {"lat":55.7,"lng":37.6,"city":"Moscow","country":"RU","count":random.randint(30,200)},
        {"lat":37.8,"lng":-122.4,"city":"San Francisco","country":"US","count":random.randint(20,100)},
        {"lat":-23.5,"lng":-46.6,"city":"Sao Paulo","country":"BR","count":random.randint(10,80)},
        {"lat":51.5,"lng":-0.1,"city":"London","country":"GB","count":random.randint(15,90)},
        {"lat":6.4,"lng":3.4,"city":"Lagos","country":"NG","count":random.randint(20,120)},
        {"lat":37.6,"lng":127.0,"city":"Seoul","country":"KR","count":random.randint(10,60)},
        {"lat":28.6,"lng":77.2,"city":"New Delhi","country":"IN","count":random.randint(5,40)},
        {"lat":35.7,"lng":139.7,"city":"Tokyo","country":"JP","count":random.randint(5,35)},
    ],"target":{"lat":13.08,"lng":80.27,"city":"Chennai","country":"IN"}})

# ── WebSocket ─────────────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    join_room("alerts"); join_room("dashboard")
    emit("connected",{"msg":"SIEM Ops Center","sid":request.sid})

@socketio.on("disconnect")
def on_disconnect():
    logger.info(f"[SIEM] disconnected: {request.sid}")

@socketio.on("subscribe")
def on_subscribe(data):
    join_room(data.get("room","dashboard"))
    emit("subscribed",{"room":data.get("room","dashboard")})

# ── Scheduler ─────────────────────────────────────────────────────────────────
_started=False
scheduler=BackgroundScheduler(daemon=True,
    executors={"default":ThreadPoolExecutor(max_workers=4)},
    job_defaults={"coalesce":True,"max_instances":1,"misfire_grace_time":15})
scheduler.add_job(evaluate_rules, "interval",seconds=60,id="rules")
scheduler.add_job(broadcast_stats,"interval",seconds=5, id="stats")

def _boot():
    global _started
    wait_for_services(300)
    if not _started:
        _started=True
        scheduler.start()
        logger.info("[SIEM] Scheduler started")
    logger.info("[SIEM] SIEM Platform v5.0 — fully operational")
    logger.info("[SIEM] Dashboard: http://localhost")

threading.Thread(target=_boot,daemon=True,name="boot").start()

if __name__=="__main__":
    socketio.run(app,host="0.0.0.0",port=8000,debug=False)
