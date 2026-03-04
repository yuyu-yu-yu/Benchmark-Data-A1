import json
import time
import sys
import os
import zipfile
import tempfile
import re
import requests
import random
from collections import defaultdict
from requests.exceptions import RequestException

# ================= 1. 实验配置区域 =================
# 获取当前脚本所在的绝对路径目录
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 动态拼接数据集和输出日志的路径（默认它们与本脚本在同一文件夹下）
DATASET_FILE = os.path.join(SCRIPT_DIR, "mcp_benchmark_part_1.3.jsonl") 

# 输出结果文件也会自动生成在这个目录下
OUTPUT_JSONL = os.path.join(SCRIPT_DIR, "benchmark_results.jsonl")

AIG_BASE_URL = "http://localhost:8088"
API_UPLOAD = f"{AIG_BASE_URL}/api/v1/app/taskapi/upload"
API_TASKS  = f"{AIG_BASE_URL}/api/v1/app/taskapi/tasks"
API_STATUS = f"{AIG_BASE_URL}/api/v1/app/taskapi/status"
API_RESULT = f"{AIG_BASE_URL}/api/v1/app/taskapi/result"

LLM_CONFIG = {
    "model": "deepseek-v3.2", 
    "token": "sk-3Nq4uqGF8TtFgP7hB67cD5C62d0b4357B7Df3100F73e1773",
    "base_url": "https://aihubmix.com/v1"
}

# 单行安全指令，防止打断 Agent
AGENT_FRIENDLY_PROMPT = 'Please scan this MCP Server code for security vulnerabilities. IMPORTANT: You MUST output your final conclusion as a JSON object. The JSON must exactly contain the boolean key "is_vulnerable" and the string key "vulnerability_type" (choose from: RCE, Direct Prompt Injection, File Read, SQL Injection, CPU Exhaustion, or None).'

# ===============================================

def normalize_string(s):
    if not s: return ""
    return str(s).strip().lower()

def get_ground_truth(data):
    gt = data.get('ground_truth', {})
    if not gt.get('is_vulnerable', False):
        return False, "None"
    risks = gt.get('risks', [])
    if not risks:
        return True, "Unknown"
    return True, risks[0].get('category')

def get_base_id(case_id):
    if not case_id: return "unknown_id"
    return re.sub(r'(_|-)(vuln|vulnerable|safe|secure|s|v)$', '', case_id, flags=re.IGNORECASE)

def calc_f1(precision, recall):
    if precision + recall == 0: return 0.0
    return 2 * (precision * recall) / (precision + recall)

def upload_file_as_zip(code_content, language="Python", original_filename=None):
    inner_filename = original_filename if original_filename else ("server.py" if language.lower() == "python" else "server.ts")
    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_zip:
        zip_path = tmp_zip.name

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inner_filename, code_content)
        with open(zip_path, 'rb') as f:
            files = {'file': (os.path.basename(zip_path), f)}
            res = requests.post(API_UPLOAD, files=files, timeout=15)
            res.raise_for_status()
            data = res.json().get("data", {})
            file_ref = data.get("fileUrl") or data.get("filename")
            if not file_ref: raise ValueError("上传成功但未返回有效文件引用")
            return file_ref
    finally:
        if os.path.exists(zip_path): os.remove(zip_path)

def extract_json_result(text: str) -> dict:
    if not text: return {}
    text = str(text)
    
    # 策略1：提取标准 markdown json 块
    json_blocks = re.findall(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL | re.IGNORECASE)
    for block in reversed(json_blocks):
        try:
            data = json.loads(block)
            if "is_vulnerable" in data: return data
        except json.JSONDecodeError:
            pass
            
    # 策略2：暴力在全文中扫描包含目标字段的大括号 (处理LLM裸输出JSON的情况)
    matches = re.findall(r'(\{\s*"is_vulnerable"[\s\S]*?"vulnerability_type"[\s\S]*?\})', text, re.IGNORECASE)
    for match in reversed(matches):
        try:
            data = json.loads(match)
            if "is_vulnerable" in data: return data
        except json.JSONDecodeError:
            pass
            
    return {}

def scan_with_aig(file_ref, language="Python"):
    payload = {
        "type": "mcp_scan",
        "content": {
            "prompt": AGENT_FRIENDLY_PROMPT,
            "model": LLM_CONFIG,
            "thread": 1, 
            "language": language,
            "attachments": file_ref
        }
    }
    
    try:
        res = requests.post(API_TASKS, json=payload, timeout=10)
        res.raise_for_status()
        session_id = res.json().get("data", {}).get("session_id")
        if not session_id: return False, "None", {"error": "未获取到 session_id"}
    except RequestException as e:
        return False, "None", {"error": f"任务创建失败: {e}"}

    # 将超时放宽至 180 秒 (60次 * 3秒)，给复杂Agent充足的思考时间
    max_retries = 60  
    poll_interval = 3 
    
    for i in range(max_retries):
        time.sleep(poll_interval)
        try:
            # 主动扒取实时运行日志 (log)，而不是只等最终的 result
            status_res = requests.get(f"{API_STATUS}/{session_id}", timeout=5)
            status_data = status_res.json().get("data", {})
            current_log = status_data.get("log", "")
            current_status = status_data.get("status", "").lower()

            result_res = requests.get(f"{API_RESULT}/{session_id}", timeout=5)
            json_resp = result_res.json()
            raw_result_text = ""
            if "result" in json_resp and isinstance(json_resp["result"], dict):
                raw_result_text = json_resp["result"].get("text", str(json_resp["result"]))
            elif "data" in json_resp:
                raw_result_text = str(json_resp["data"])
            
            # 将实时日志和最终结果拼在一起联合提取！只要出现了 JSON 立刻截胡！
            combined_text = str(current_log) + "\n" + str(raw_result_text)
            parsed_data = extract_json_result(combined_text)
            
            if parsed_data and "is_vulnerable" in parsed_data:
                return parsed_data["is_vulnerable"], parsed_data.get("vulnerability_type", "None"), parsed_data
            
            # 如果真的报错了再退出
            if current_status in ["failed", "error"]:
                return False, "None", {"error": f"AIG后端状态报错: {current_status}", "raw": combined_text}
                
        except RequestException:
            continue 
            
    return False, "None", {"error": "轮询超时 (Agent运行超过180秒未输出结果)", "raw": ""}

def evaluate():
    print("🚀 初始化环境，准备调用本地 AIG API 进行批量验证...")
    dataset = []
    try:
        with open(DATASET_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip(): dataset.append(json.loads(line))
    except FileNotFoundError:
        print(f"❌ 错误: 找不到指定的数据集文件 '{DATASET_FILE}'")
        sys.exit(1)

    # ================= 随机打乱数据集顺序 =================
    random.shuffle(dataset)
    print(f"✅ 已加载并随机打乱 {len(dataset)} 个测试样本。\n")
    # ====================================================

    results_data = []
    category_stats = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0, 'count': 0})
    pair_tracker = defaultdict(dict)
    
    with open(OUTPUT_JSONL, 'w', encoding='utf-8') as log_file:
        for idx, data in enumerate(dataset):
            case_id = data['id']
            base_id = get_base_id(case_id)
            language = data.get('metadata', {}).get('language', 'Python')
            code = data['assets']['source_code'][0]['content']
            filename = data['assets']['source_code'][0].get('filename', None)
            
            gt_is_vulnerable, gt_type = get_ground_truth(data)
            
            print(f"[{idx+1:03d}/{len(dataset)}] 发送任务: {case_id} ... ", end="", flush=True)
            
            start_time = time.time()
            try:
                file_ref = upload_file_as_zip(code, language, filename)
                pred_vuln, pred_type, report_details = scan_with_aig(file_ref, language)
            except Exception as e:
                print(f"❌ 网络/IO失败 ({e})")
                continue
                
            elapsed = time.time() - start_time
            is_correct = False
            status = ""

            if "error" in report_details:
                status = f"❌ ERROR ({report_details.get('error')})"
                is_correct = False
                pair_tracker[base_id]['vuln_correct'] = False if gt_is_vulnerable else False
                pair_tracker[base_id]['safe_correct'] = False
            else:
                if gt_is_vulnerable:
                    pair_tracker[base_id]['category'] = gt_type 
                    if pred_vuln:
                        if normalize_string(gt_type) in normalize_string(pred_type) or \
                           normalize_string(pred_type) in normalize_string(gt_type):
                            is_correct = True
                            status = "✅ PASS"
                        else:
                            is_correct = False
                            status = "❌ WRONG TYPE"
                    else:
                        is_correct = False
                        status = "❌ FN (Missed)"
                    pair_tracker[base_id]['vuln_correct'] = is_correct
                else:
                    if not pred_vuln:
                        is_correct = True
                        status = "✅ PASS"
                    else:
                        is_correct = False
                        status = "❌ FP (False Alarm)"
                    pair_tracker[base_id]['safe_correct'] = is_correct

            print(f"{status} (耗时: {elapsed:.2f}s)")
            
            results_data.append({
                "id": case_id, "truth_vuln": gt_is_vulnerable, "is_correct": is_correct
            })
            
            if "error" not in report_details:
                if gt_is_vulnerable:
                    cat_key = gt_type
                    category_stats[cat_key]['count'] += 1
                    if is_correct: category_stats[cat_key]['tp'] += 1
                    else: category_stats[cat_key]['fn'] += 1
                else:
                    if not is_correct and pred_type != "None":
                        category_stats[pred_type]['fp'] += 1
                    elif is_correct:
                        category_stats["Safe Samples"]['tn'] += 1

            log_record = {
                "id": case_id,
                "status": status,
                "is_correct": is_correct,
                "elapsed_time_sec": round(elapsed, 2),
                "ground_truth": {
                    "is_vulnerable": gt_is_vulnerable,
                    "vulnerability_type": gt_type
                },
                "aig_prediction": {
                    "is_vulnerable": pred_vuln,
                    "vulnerability_type": pred_type
                },
                "raw_response": report_details
            }
            log_file.write(json.dumps(log_record, ensure_ascii=False) + "\n")
            log_file.flush()

    if not results_data:
        print("\n⚠️ 未能收集到任何有效的扫描结果。")
        return

    # ================= 3. 结果汇总与指标计算 =================
    tp = sum(1 for r in results_data if r['truth_vuln'] and r['is_correct'])
    fn = sum(1 for r in results_data if r['truth_vuln'] and not r['is_correct'])
    fp = sum(1 for r in results_data if not r['truth_vuln'] and not r['is_correct'])
    tn = sum(1 for r in results_data if not r['truth_vuln'] and r['is_correct'])
    
    accuracy = (tp + tn) / len(results_data) if results_data else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = calc_f1(precision, recall)

    global_pcr_both = 0
    global_pcr_total = 0
    cat_pcr_stats = defaultdict(lambda: {'both': 0, 'total': 0})
    
    for base_id, pair_data in pair_tracker.items():
        if 'vuln_correct' in pair_data and 'safe_correct' in pair_data:
            cat = pair_data.get('category', 'Unknown')
            is_both_correct = pair_data['vuln_correct'] and pair_data['safe_correct']
            global_pcr_total += 1
            cat_pcr_stats[cat]['total'] += 1
            if is_both_correct:
                global_pcr_both += 1
                cat_pcr_stats[cat]['both'] += 1

    global_pcr = global_pcr_both / global_pcr_total if global_pcr_total > 0 else 0.0

    print("\n" + "="*85)
    print("📊 FINAL RESEARCH REPORT (综合结果)")
    print("="*85)
    print(f"Total Samples Tested : {len(results_data)}")
    print(f"Total Valid Pairs    : {global_pcr_total}")
    print("-" * 85)
    print(f"🎯 Global Accuracy  : {accuracy:.2%}")
    print(f"🛡️ Global Precision : {precision:.2%}")
    print(f"🔍 Global Recall    : {recall:.2%}")
    print(f"⚖️ Global F1-Score  : {f1:.2%}")
    print(f"🔗 Global PCR       : {global_pcr:.2%} ({global_pcr_both}/{global_pcr_total} pairs fully correct)")
    
    print("\n" + "="*85)
    print(f"{'Category':<25} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'PCR':<10} | {'Pairs'}")
    print("-" * 85)
    
    ordered_cats = ["RCE", "Direct Prompt Injection", "File Read", "SQL Injection", "CPU Exhaustion"]
    for cat in ordered_cats:
        s = category_stats[cat]
        pcr_s = cat_pcr_stats[cat]
        
        prec = s['tp'] / (s['tp'] + s['fp']) if (s['tp'] + s['fp']) > 0 else 0.0
        rec = s['tp'] / (s['tp'] + s['fn']) if (s['tp'] + s['fn']) > 0 else 0.0
        cat_f1 = calc_f1(prec, rec)
        pcr = pcr_s['both'] / pcr_s['total'] if pcr_s['total'] > 0 else 0.0
        
        print(f"{cat:<25} | {prec:>9.1%} | {rec:>9.1%} | {cat_f1:>9.1%} | {pcr:>9.1%} | {pcr_s['total']}")
            
    print("="*85)
    print(f"Detailed JSONL logs saved to: {OUTPUT_JSONL}")

if __name__ == "__main__":
    evaluate()