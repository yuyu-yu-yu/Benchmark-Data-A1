import json
import tempfile
import subprocess
import os

def map_semgrep_rule(rule_id: str) -> str:
    """将 Semgrep 的原生规则 ID 映射到我们的 5 种分类"""
    rule_id = rule_id.lower()
    
    if any(k in rule_id for k in ["exec", "subprocess", "os-system", "eval", "command-injection", "injection.os"]):
        return "RCE"
    elif any(k in rule_id for k in ["sql"]):
        return "SQL Injection"
    elif any(k in rule_id for k in ["path-traversal", "file", "open", "read"]):
        return "File Read"
    elif any(k in rule_id for k in ["xml", "dos", "exhaustion", "regex"]):
        return "CPU Exhaustion"
    else:
        # 如果命中其他安全规则但不在分类内，归入 Unknown
        return "Unknown"

def scan_python_code(source_code: str):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as temp_file:
        temp_file.write(source_code)
        temp_path = temp_file.name

    is_vulnerable = False
    pred_type = "None"
    raw_findings = []

    try:
        # 调用 Semgrep，加载官方的 Python 和通用安全规则库，强制输出 JSON
        result = subprocess.run(
            ['semgrep', 'scan', '--config', 'p/python', '--config', 'p/security-audit', '--json', temp_path],
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        
        try:
            report = json.loads(result.stdout)
            results_list = report.get("results", [])
            raw_findings = results_list
            
            if results_list:
                is_vulnerable = True
                detected_types = set()
                
                for issue in results_list:
                    check_id = issue.get("check_id", "")
                    mapped_type = map_semgrep_rule(check_id)
                    if mapped_type != "Unknown":
                        detected_types.add(mapped_type)
                
                if detected_types:
                    pred_type = " | ".join(detected_types)
                else:
                    pred_type = "Unknown"
                    
        except json.JSONDecodeError:
            pred_type = "Error: Semgrep Execution Failed"
            raw_findings = {"stdout": result.stdout, "stderr": result.stderr}

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    report_dict = {
        "is_vulnerable": is_vulnerable,
        "vulnerability_type": pred_type,
        "reasoning": f"Semgrep detected {len(raw_findings)} issues.",
        "raw_semgrep_output": raw_findings
    }
    

    return is_vulnerable, report_dict
