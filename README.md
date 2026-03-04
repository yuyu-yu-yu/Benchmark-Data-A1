# MCP Risk Benchmark Evaluation

This project aims to benchmark various security scanning tools and LLM-based Agents to evaluate their capabilities in detecting common security vulnerabilities in MCP (Model Context Protocol) Servers.

## 🛡️ Vulnerability Categories Evaluated

This project focuses on detecting the following 5 types of vulnerabilities:
* **RCE** (Remote Code Execution / Command Injection)
* **SQL Injection**
* **File Read** (Arbitrary File Read / Path Traversal)
* **CPU Exhaustion** (CPU Exhaustion / Denial of Service)
* **Direct Prompt Injection**

## 📁 Directory Structure

* **`tools/`**: Contains wrappers and mapping logic for various scanning tools, such as `bandit_tool.py` and `semgrep_tool.py`.
* **`scripts/`**: Contains the main evaluation scripts for batch testing, such as `evaluate_bandit.py` and `evaluate_with_aig.py`.
* **`results/`**: Stores generated log files, failure case analyses, and detailed metric reports (including Accuracy, Precision, Recall, F1-Score, and PCR).
* **`dataset/`**: Contains the dataset of vulnerable and secure code samples for testing (e.g., `mcp_risk_benchmark_v5.jsonl`).

## 🚀 How to Run

**1. Prepare the Dataset**
Ensure the test dataset `.jsonl` file is placed in the correct path and update the `DATASET_FILE` path variable in the corresponding script under the `scripts/` directory.

**2. Install Dependencies**
You can install the required base dependencies using pip:

    pip install bandit semgrep openai requests

**3. Execute Evaluation**
Navigate to the `scripts` directory and run the tool you want to test. For example, to evaluate Bandit:

    cd scripts
    python evaluate_bandit.py

> **Note:** Before running `evaluate_benchmark_llm.py` or `evaluate_with_aig.py`, please ensure that the LLM API Key and base URL are correctly configured within the scripts.

## 📊 Evaluation Results Summary

The latest scanning logs and detailed metric information are saved in the `results/` directory. Our evaluation not only calculates the traditional F1-Score but also introduces PCR (Pairwise Correctness Rate) to verify the model's judgment stability across positive and negative sample pairs.
