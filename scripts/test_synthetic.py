import sys
from pathlib import Path
import numpy as np,pandas as pd
sys.path.insert(0,str(Path(__file__).parents[1]/"src"))
from fileless_detector.train_model import train
r=np.random.default_rng(42);n=200
d=pd.DataFrame({"cpu_usage":r.normal(20,5,n),"ram_usage_mb":r.normal(6000,300,n),"process_count":r.normal(180,10,n),"powershell_process_count":0,"wmic_process_count":0,"mshta_process_count":0,"api_calls_per_sec":r.normal(1,.2,n),"suspended_process_created":0,"command_line_entropy":r.normal(3,.2,n),"network_connections_from_system_process":0,"remote_thread_events":0,"process_access_events":0,"command_text":"normal activity"})
d.to_csv("baseline_synthetic.csv",index=False);print(train("baseline_synthetic.csv","artifacts_synthetic"))
