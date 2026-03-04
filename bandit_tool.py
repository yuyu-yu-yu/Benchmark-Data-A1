import json
import tempfile
import subprocess
import os

# ==========================================
# Bandit 规则 ID 到你的 5 种漏洞分类的完整映射表
# ==========================================
BANDIT_MAPPING = {
    # ---------------------------------------------------------
    # 1. RCE (命令执行 / 代码执行) - Bandit 的强项
    # ---------------------------------------------------------
    "B602": "RCE", # subprocess_popen_with_shell_equals_true
    "B603": "RCE", # subprocess_without_shell_equals_true
    "B604": "RCE", # any_other_function_with_shell_equals_true
    "B605": "RCE", # start_process_with_a_shell
    "B606": "RCE", # start_process_with_no_shell
    "B607": "RCE", # start_process_with_partial_path
    "B609": "RCE", # linux_commands_wildcard_injection
    "B102": "RCE", # exec_used
    "B307": "RCE", # eval_used
    "B404": "RCE", # import_subprocess (高敏规则：只要导入了subprocess就告警)

    # ---------------------------------------------------------
    # 2. SQL Injection (SQL 注入)
    # ---------------------------------------------------------
    "B608": "SQL Injection", # hardcoded_sql_expressions (字符串拼接SQL)
    "B614": "SQL Injection", # django_rawsql_used

    # ---------------------------------------------------------
    # 3. CPU Exhaustion (CPU 耗尽 / 拒绝服务 DoS)
    # Bandit 不支持正则 ReDoS 检测，但支持 XML 炸弹（Billion Laughs）导致的耗尽
    # ---------------------------------------------------------
    "B313": "CPU Exhaustion", # xml_bad_cElementTree
    "B314": "CPU Exhaustion", # xml_bad_ElementTree
    "B315": "CPU Exhaustion", # xml_bad_expatreader
    "B318": "CPU Exhaustion", # xml_bad_minidom
    "B320": "CPU Exhaustion", # xml_bad_lxml
    "B405": "CPU Exhaustion", # import_xml_etree
    "B406": "CPU Exhaustion", # import_xml_sax
    "B407": "CPU Exhaustion", # import_xml_expat
    "B408": "CPU Exhaustion", # import_xml_minidom
    "B409": "CPU Exhaustion", # import_xmlrpclib

    # ---------------------------------------------------------
    # 4. File Read (任意文件读取 / 目录遍历)
    # Bandit 缺乏强大的数据流污点分析，只能抓一些硬编码或不安全的临时文件操作
    # ---------------------------------------------------------
    "B108": "File Read", # hardcoded_tmp_directory (不安全的硬编码临时目录访问)

    # ---------------------------------------------------------
    # 5. Direct Prompt Injection (提示词注入)
    # Bandit 规则库中数量为 0。完全无法检测。
    # ---------------------------------------------------------
}

def scan_python_code(source_code: str):
    """
    接收 Python 源码，写入临时文件，调用 Bandit 扫描并返回符合你原有格式的 JSON
    """
    # 1. 将待测代码写入临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as temp_file:
        temp_file.write(source_code)
        temp_path = temp_file.name

    is_vulnerable = False
    pred_type = "None"
    raw_findings = []

    try:
        # 2. 调用命令行执行 Bandit，并强制输出为 JSON 格式
        # -q 表示安静模式（减少多余打印），-f json 表示输出 json
        result = subprocess.run(
            ['bandit', '-q', '-f', 'json', temp_path],
            capture_output=True,
            text=True
        )
        
        # 3. 解析 Bandit 的 JSON 输出
        try:
            report = json.loads(result.stdout)
            results_list = report.get("results", [])
            raw_findings = results_list
            
            if results_list:
                is_vulnerable = True
                detected_types = set()
                
                # 提取所有的报警，并尝试映射到我们的分类体系
                for issue in results_list:
                    test_id = issue.get("test_id")
                    test_name = issue.get("test_name", "Unknown")
                    # 如果在映射表里，就转成对应的 "RCE" 等，否则保留原始名字
                    mapped_type = BANDIT_MAPPING.get(test_id, test_name)
                    detected_types.add(mapped_type)
                
                # 将所有检测到的类型拼接（例如 "RCE | SQL Injection"），方便评估脚本通过 in 判定
                pred_type = " | ".join(detected_types)
                
        except json.JSONDecodeError:
            # 万一解析失败（极少数情况）
            pred_type = "Error: Bandit Execution Failed"
            raw_findings = {"stdout": result.stdout, "stderr": result.stderr}

    finally:
        # 4. 扫描完毕，删除临时文件
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # 5. 构造和 LLM 接口完全一致的返回格式
    report_dict = {
        "is_vulnerable": is_vulnerable,
        "vulnerability_type": pred_type,
        "reasoning": f"Bandit detected {len(raw_findings)} issues.",
        "raw_bandit_output": raw_findings
    }
    
    return is_vulnerable, report_dict

# 简单的测试代码（你可以直接运行这个文件看看效果）
if __name__ == "__main__":
    test_code = """
import os
def ping(host):
    os.system(f"ping -c 1 {host}")
"""
    vuln, report = scan_python_code(test_code)
    print(f"Is Vulnerable: {vuln}")
    print(f"Type: {report['vulnerability_type']}")