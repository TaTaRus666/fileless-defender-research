"""Rule layer minh bạch, chỉ chọn event cần AI phân tích."""
from pathlib import Path
OFFICE={"winword.exe","excel.exe","powerpnt.exe","outlook.exe"}
def rule_reasons(e,entropy_threshold=4.6):
    c=str(e.get("command_line","")).lower();p=str(e.get("process_name","")).lower(); parent=Path(str(e.get("parent_image","")).lower()).name;r=[]
    if p in {"powershell.exe","pwsh.exe"} and any(x in c for x in ("-enc","-encodedcommand","-w hidden","-windowstyle hidden","-executionpolicy bypass")):r.append("PowerShell có tham số ẩn/encoded/bypass")
    if e.get("suspended_process_created") and parent in OFFICE:r.append("Office tạo tiến trình suspended")
    if float(e.get("command_line_entropy",0))>=entropy_threshold:r.append("Command-line entropy cao")
    if int(e.get("event_id",0)) in (8,10):r.append("Sysmon remote thread/process access")
    return r
def rule_filter(event,whitelist=None):
    if whitelist and str(event.get("process_name","")).lower() in {x.lower() for x in whitelist.get("process_names",[])}:return False
    return bool(rule_reasons(event))
