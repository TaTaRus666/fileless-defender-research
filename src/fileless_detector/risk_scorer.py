"""Đổi decision score thành mức rủi ro và z-deviation dễ diễn giải."""
import numpy as np
class RiskScorer:
 def __init__(self,calibration,names):self.calibration=calibration;self.names=names
 def assess(self,decision,vector,reasons):
  a=-float(decision);p50,p95,p99=[self.calibration[x] for x in ("anomaly_p50","anomaly_p95","anomaly_p99")]
  score=20+40*(a-p50)/max(p95-p50,1e-6) if a<=p95 else 60+35*(a-p95)/max(p99-p95,1e-6);score=round(float(np.clip(score,0,100)),2);level="Low" if score<50 else ("Medium" if score<=90 else "High/Critical")
  idx=np.argsort(np.abs(vector[:len(self.names)]))[::-1][:4];return {"label":"anomaly" if score>=50 else "normal","risk_score":score,"level":level,"explanation":{"rule_signals":reasons,"feature_deviations":[{"feature":self.names[i],"z_deviation":round(float(vector[i]),2)} for i in idx]}}
