import json
import re
from openai import OpenAI

# ==========================================
# 1. 配置区域
# ==========================================
API_KEY = "xxx"  # 请替换你的 Key
BASE_URL = "xxx"
DEFAULT_MODEL = "gpt-5-mini"

client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=120.0)

# ==========================================
# 2. 漏洞详细定义 (Prompt 核心) —— 对照组 (Baseline)
# ==========================================
VULNERABILITY_TAXONOMY = """
1. RCE
2. Direct Prompt Injection
3. File Read
4. SQL Injection
5. CPU Exhaustion
"""

SYSTEM_PROMPT_TEMPLATE = f"""
You are an expert security researcher specializing in Python code auditing for MCP (Model Context Protocol) servers.

Your Goal: Analyze the provided Python code and detect if it contains any of the following 5 specific vulnerabilities.

Vulnerability Categories:
{VULNERABILITY_TAXONOMY}

Analysis Steps:
1. Read the code carefully, paying attention to the imports and overall logic.
2. Determine if the code logic contains any of the specific vulnerabilities listed above based on your own knowledge.

Output Requirements:
1. Output MUST be in valid JSON format.
2. If a vulnerability is found, set "is_vulnerable" to true.
3. You MUST use the EXACT Name from the list above for "vulnerability_type" (e.g., output "File Read", DO NOT output "Path Traversal").

JSON Output Structure:
{{
    "is_vulnerable": true,
    "vulnerability_type": "RCE",
    "reasoning": "Briefly explain your reasoning here..."
}}
"""

def call_llm(system_prompt: str, user_prompt: str, model: str) -> str:
    """调用 LLM"""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            stream=False,
            temperature=0.0 # 保持0温度以获得最稳定的格式
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"\n[API Error] {str(e)}")
        return ""

def clean_json_output(raw_text: str) -> dict:
    """清洗并解析 JSON"""
    try:
        text = re.sub(r'```json\s*', '', raw_text)
        text = re.sub(r'```', '', text).strip()
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": "JSON Parse Error", "raw_text": raw_text}

def scan_python_code(source_code: str, model: str = DEFAULT_MODEL):
    """主扫描函数"""
    user_prompt = f"Code to Analyze:\n\n{source_code}"
    
    raw_response = call_llm(SYSTEM_PROMPT_TEMPLATE, user_prompt, model)
    result = clean_json_output(raw_response)
    
    if isinstance(result, dict) and "is_vulnerable" in result:
        return result["is_vulnerable"], result
    else:
        return False, result
