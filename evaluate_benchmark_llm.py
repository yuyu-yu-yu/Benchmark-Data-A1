import json
import time
import os
import random
import re
from collections import defaultdict

try:
    from initial_version_tool import scan_python_code
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    try:
        from initial_version_tool import scan_python_code
    except ImportError:
        print("Error: initial_version_tool.py not found.")
        sys.exit(1)

# ================= 配置区域 =================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_FILE = os.path.join(SCRIPT_DIR, "mcp_risk_benchmark_v5.jsonl") 
OUTPUT_LOG = os.path.join(SCRIPT_DIR, "benchmark_final_xxx_report.log")
# ===========================================

def normalize_string(s):
    if not s: return ""
    return str(s).strip().lower()

def get_ground_truth(data):
    """从清洗后的数据集中获取真值"""
    gt = data.get('ground_truth', {})
    if not gt.get('is_vulnerable', False):
        return False, "None"
    
    risks = gt.get('risks', [])
    if not risks:
        return True, "Unknown"
        
    return True, risks[0].get('category')

def get_base_id(case_id):
    """
    提取配对的基础 ID。
    """
    if not case_id: return "unknown_id"
    # 移除末尾的 _vuln, -vuln, _safe, -safe 等标识
    return re.sub(r'(_|-)(vuln|vulnerable|safe|secure|s|v)$', '', case_id, flags=re.IGNORECASE)

def calc_f1(precision, recall):
    if precision + recall == 0:
        return 0.0
    return 2 * (precision * recall) / (precision + recall)

def calculate_global_metrics(results):
    """计算全局基础指标"""
    tp = sum(1 for r in results if r['truth_vuln'] and r['is_correct'])
    fn = sum(1 for r in results if r['truth_vuln'] and not r['is_correct'])
    fp = sum(1 for r in results if not r['truth_vuln'] and not r['is_correct'])
    tn = sum(1 for r in results if not r['truth_vuln'] and r['is_correct'])
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = calc_f1(precision, recall)
    
    return {
        "accuracy": accuracy, "recall": recall, 
        "precision": precision, "f1": f1,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn
    }

def main():
    if not os.path.exists(DATASET_FILE):
        print(f"Error: Dataset not found: {DATASET_FILE}")
        return

    print(f"🚀 Starting Benchmark on: {os.path.basename(DATASET_FILE)}")
    
    dataset = []
    with open(DATASET_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip(): dataset.append(json.loads(line))
            
    random.shuffle(dataset)
    print(f"✅ Loaded {len(dataset)} samples.\n")

    results_data = []
    category_stats = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0, 'count': 0})
    
    # 记录配对数据用于计算 PCR
    # 结构: pair_tracker[base_id] = {'category': str, 'vuln_correct': bool, 'safe_correct': bool}
    pair_tracker = defaultdict(dict)

    with open(OUTPUT_LOG, 'w', encoding='utf-8') as log_file:
        for idx, data in enumerate(dataset):
            case_id = data.get('id')
            base_id = get_base_id(case_id)
            code = data.get('assets', {}).get('source_code', [{}])[0].get('content', "")
            
            gt_is_vulnerable, gt_type = get_ground_truth(data)
            
            print(f"[{idx+1}/{len(dataset)}] {case_id}...", end="", flush=True)
            
            start = time.time()
            if code:
                pred_vuln, report = scan_python_code(code)
            else:
                pred_vuln = False; report = {}
            elapsed = time.time() - start
            
            pred_type = report.get("vulnerability_type", "None")
            is_correct = False
            status = ""
            
            if gt_is_vulnerable:
                # 记录该配对的漏洞类型
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

            print(f" {status} ({elapsed:.2f}s)")
            
            results_data.append({
                "id": case_id,
                "truth_vuln": gt_is_vulnerable,
                "is_correct": is_correct
            })
            
            # 分类统计 (将 fp 也归入预测出的类型用于精准计算 Precision)
            if gt_is_vulnerable:
                cat_key = gt_type
                category_stats[cat_key]['count'] += 1
                if is_correct: category_stats[cat_key]['tp'] += 1
                else: category_stats[cat_key]['fn'] += 1
            else:
                # 真实安全的样本，如果误报了某个类型，记作该类型的 FP
                if not is_correct and pred_type != "None":
                    category_stats[pred_type]['fp'] += 1
                elif is_correct:
                    category_stats["Safe Samples"]['tn'] += 1

            if not is_correct:
                log_file.write(f"Case: {case_id}\n")
                log_file.write(f"Status: {status}\n")
                log_file.write(f"Exp: {gt_type} | Got: {pred_type}\n")
                log_file.write("-" * 30 + "\n")
                log_file.flush()

    # === 计算 PCR ===
    global_pcr_both = 0
    global_pcr_total = 0
    cat_pcr_stats = defaultdict(lambda: {'both': 0, 'total': 0})
    
    for base_id, pair_data in pair_tracker.items():
        # 仅当成对数据（既包含有毒又包含安全样本的测试结果）完整时才计算
        if 'vuln_correct' in pair_data and 'safe_correct' in pair_data:
            cat = pair_data.get('category', 'Unknown')
            is_both_correct = pair_data['vuln_correct'] and pair_data['safe_correct']
            
            global_pcr_total += 1
            cat_pcr_stats[cat]['total'] += 1
            if is_both_correct:
                global_pcr_both += 1
                cat_pcr_stats[cat]['both'] += 1

    global_pcr = global_pcr_both / global_pcr_total if global_pcr_total > 0 else 0.0

    # === 生成最终报告 ===
    metrics = calculate_global_metrics(results_data)
    
    print("\n" + "="*85)
    print("📊 FINAL RESEARCH REPORT (综合结果)")
    print("="*85)
    
    print(f"Total Samples Tested : {len(dataset)}")
    print(f"Total Valid Pairs    : {global_pcr_total}")
    print("-" * 85)
    
    print(f"🎯 Global Accuracy  : {metrics['accuracy']:.2%}")
    print(f"🛡️ Global Precision : {metrics['precision']:.2%}")
    print(f"🔍 Global Recall    : {metrics['recall']:.2%}")
    print(f"⚖️ Global F1-Score  : {metrics['f1']:.2%}")
    print(f"🔗 Global PCR       : {global_pcr:.2%} ({global_pcr_both}/{global_pcr_total} pairs fully correct)")
    
    print("\n" + "="*85)
    print(f"{'Category':<25} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'PCR':<10} | {'Pairs'}")
    print("-" * 85)
    
    ordered_cats = [
        "RCE", "Direct Prompt Injection", "File Read", "SQL Injection", "CPU Exhaustion"
    ]
    
    for cat in ordered_cats:
        s = category_stats[cat]
        pcr_s = cat_pcr_stats[cat]
        
        # 计算各种类型的指标
        prec = s['tp'] / (s['tp'] + s['fp']) if (s['tp'] + s['fp']) > 0 else 0.0
        rec = s['tp'] / (s['tp'] + s['fn']) if (s['tp'] + s['fn']) > 0 else 0.0
        f1 = calc_f1(prec, rec)
        pcr = pcr_s['both'] / pcr_s['total'] if pcr_s['total'] > 0 else 0.0
        
        print(f"{cat:<25} | {prec:>9.1%} | {rec:>9.1%} | {f1:>9.1%} | {pcr:>9.1%} | {pcr_s['total']}")
            
    print("="*85)
    print(f"See {OUTPUT_LOG} for failure details.")

if __name__ == "__main__":
    main()