"""Collector chỉ đọc psutil và Windows Event Log, không sửa hệ thống."""
from datetime import datetime, timezone
import psutil
class DataCollector:
 def snapshot(self):
  names=[]
  for p in psutil.process_iter(["name"]):
   try:names.append((p.info["name"] or "").lower())
   except (psutil.NoSuchProcess,psutil.AccessDenied):pass
  return {"timestamp":datetime.now(timezone.utc).isoformat(),"cpu_usage":psutil.cpu_percent(),"ram_usage_mb":psutil.virtual_memory().used/1048576,"process_count":len(names),"powershell_process_count":sum(n in ("powershell.exe","pwsh.exe") for n in names),"wmic_process_count":names.count("wmic.exe"),"mshta_process_count":names.count("mshta.exe")}
 def read_security_events(self): return [] # Cài Sysmon/config reader ở pha triển khai Windows.
 def poll(self):
  s=self.snapshot();e=self.read_security_events();return [{**s,**x} for x in e] or [{**s,"event_id":0,"command_line":"","process_name":""}]
