"""Tiền xử lý telemetry: gom time-window, entropy và TF-IDF."""
import math
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
NUMERIC_FEATURES=["cpu_usage","ram_usage_mb","process_count","powershell_process_count","wmic_process_count","mshta_process_count","api_calls_per_sec","suspended_process_created","command_line_entropy","network_connections_from_system_process","remote_thread_events","process_access_events"]
def shannon_entropy(text):
    if not text:return 0.0
    c=Counter(text); n=len(text); return -sum((v/n)*math.log2(v/n) for v in c.values())
def aggregate_windows(events,window_seconds=5):
    if not events:return pd.DataFrame(columns=NUMERIC_FEATURES+["command_text"])
    f=pd.DataFrame(events)
    for col,default in {"command_line":"","process_name":"","event_id":0,"suspended_process_created":False}.items():
        if col not in f:f[col]=default
    f["timestamp"]=pd.to_datetime(f["timestamp"],utc=True); f["window"]=f.timestamp.dt.floor(f"{window_seconds}s")
    rows=[]
    for t,g in f.groupby("window"):
        cmd=g.command_line.fillna("").astype(str).tolist(); names=g.process_name.fillna("").str.lower(); ids=pd.to_numeric(g.event_id,errors="coerce").fillna(0)
        rows.append({"window_start":t.isoformat(),"cpu_usage":float(g.cpu_usage.mean()),"ram_usage_mb":float(g.ram_usage_mb.mean()),"process_count":float(g.process_count.mean()),"powershell_process_count":float(g.powershell_process_count.mean()),"wmic_process_count":float(g.wmic_process_count.mean()),"mshta_process_count":float(g.mshta_process_count.mean()),"api_calls_per_sec":len(g)/window_seconds,"suspended_process_created":int(g.suspended_process_created.astype(bool).sum()),"command_line_entropy":float(np.mean([shannon_entropy(x) for x in cmd])),"network_connections_from_system_process":int(((ids==3)&names.isin(["svchost.exe","services.exe","lsass.exe"])).sum()),"remote_thread_events":int((ids==8).sum()),"process_access_events":int((ids==10).sum()),"command_text":" ".join(cmd) or "no_command"})
    return pd.DataFrame(rows)
class FeatureEncoder:
    def __init__(self):self.scaler=StandardScaler();self.vectorizer=TfidfVectorizer(max_features=32,ngram_range=(1,2));self.fitted=False
    @property
    def feature_names(self):return NUMERIC_FEATURES+["tfidf_"+x for x in (self.vectorizer.get_feature_names_out() if self.fitted else [])]
    def _parts(self,w,fit=False):
        n=w.reindex(columns=NUMERIC_FEATURES,fill_value=0).astype(float).to_numpy(); t=w.get("command_text",pd.Series("no_command",index=w.index)).fillna("no_command").astype(str).mask(lambda x:x.str.strip().eq(""),"no_command")
        a=self.scaler.fit_transform(n) if fit else self.scaler.transform(n); b=self.vectorizer.fit_transform(t).toarray() if fit else self.vectorizer.transform(t).toarray();return np.hstack([a,b]).astype(np.float32)
    def fit_transform(self,w):self.fitted=True;return self._parts(w,True)
    def transform(self,w):return self._parts(w,False)
