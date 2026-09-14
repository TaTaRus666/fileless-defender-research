"""SDK non-blocking: cảnh báo callback, không kill process."""
import json,threading
from pathlib import Path
import joblib
from .data_collector import DataCollector
from .feature_engineering import aggregate_windows,shannon_entropy
from .rule_filter import rule_filter,rule_reasons
from .risk_scorer import RiskScorer
class DetectorAgent:
 def __init__(self,artifact_dir,callback=None,poll_seconds=1):
  p=Path(artifact_dir);a=joblib.load(p/"baseline_audit.joblib");self.model,self.encoder=a["model"],a["encoder"];self.meta=json.loads((p/"model_metadata.json").read_text());self.scorer=RiskScorer(self.meta,self.meta["numeric_feature_names"]);self.callback,self.poll_seconds=callback,poll_seconds;self.collector=DataCollector();self.stop_event=threading.Event();self.thread=None
 def analyze(self,event):
  event=dict(event);event["command_line_entropy"]=shannon_entropy(str(event.get("command_line","")));r=rule_reasons(event)
  if not rule_filter(event):return {"label":"not_queued","risk_score":0,"level":"Low","explanation":{}}
  x=self.encoder.transform(aggregate_windows([event],max(1,int(self.poll_seconds))));return self.scorer.assess(self.model.decision_function(x)[0],x[0],r)
 def _run(self):
  while not self.stop_event.is_set():
   for e in self.collector.poll():
    r=self.analyze(e)
    if self.callback and r["level"]!="Low":self.callback(r)
   self.stop_event.wait(self.poll_seconds)
 def start(self):
  if not self.thread or not self.thread.is_alive():self.stop_event.clear();self.thread=threading.Thread(target=self._run,daemon=True);self.thread.start()
 def stop(self):self.stop_event.set();self.thread and self.thread.join(self.poll_seconds+2)
