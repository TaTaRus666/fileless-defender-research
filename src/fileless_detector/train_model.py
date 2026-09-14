"""Train baseline sạch: IsolationForest, audit bundle và ONNX CPU."""
import argparse,json
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import IsolationForest
from .feature_engineering import FeatureEncoder,NUMERIC_FEATURES
def train(input_csv,output_dir,contamination=.05):
 w=pd.read_csv(input_csv)
 if len(w)<30:raise ValueError("Cần ít nhất 30 cửa sổ baseline sạch")
 enc=FeatureEncoder();x=enc.fit_transform(w);m=IsolationForest(n_estimators=100,contamination=contamination,random_state=42,n_jobs=1).fit(x);d=m.decision_function(x);o=Path(output_dir);o.mkdir(parents=True,exist_ok=True);joblib.dump({"model":m,"encoder":enc},o/"baseline_audit.joblib")
 meta={"anomaly_p50":float(np.percentile(-d,50)),"anomaly_p95":float(np.percentile(-d,95)),"anomaly_p99":float(np.percentile(-d,99)),"numeric_feature_names":NUMERIC_FEATURES,"feature_names":enc.feature_names};(o/"model_metadata.json").write_text(json.dumps(meta),encoding="utf8")
 from skl2onnx import to_onnx
 (o/"fileless_detector.onnx").write_bytes(to_onnx(m,x[:1],target_opset={"":15,"ai.onnx.ml":3}).SerializeToString());return {"samples":len(w),"output":str(o/"fileless_detector.onnx")}
if __name__=="__main__":
 p=argparse.ArgumentParser();p.add_argument("--input",required=True);p.add_argument("--output-dir",default="artifacts");a=p.parse_args();print(train(a.input,a.output_dir))
