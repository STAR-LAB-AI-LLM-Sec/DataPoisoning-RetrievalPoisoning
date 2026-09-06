#!/usr/bin/env bash
# =============================================================================
# 防守方终端脚本 —— SupportBot 客服工单助手攻防基准（Baseline：账户来源校验拦截）
#
# 交互式配置：
#   1) 选择评测模式：
#        - 真实大模型 Agent API（按评测规范使用真实大模型实测）
#        - 离线确定性规则 Agent 模拟器（无需任何 API，秒级验证流水线）
#   2) 若选择真实 API，交互式输入 Agent Base URL / API Key / Model ID
#
# 在新机器上以默认参数运行：
#     pip install -r requirements.txt
#     bash run_defense.sh
#
# 输出：AccountOriginGuard 面对全部官方攻击（攻击 Baseline / NoOp / 规则违规注入）
#       的防御胜率、误伤率资格线（≤10%）与清洁行为保持率
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

# 指定解释器：默认 python，可用 PYTHON 环境变量覆盖
PY="${PYTHON:-python}"

echo ">>> [run_defense] 防守方 Baseline 评测（AccountOriginGuard）"
read -rp "使用真实大模型 Agent API 评测？[y/N] " USE_API
if [[ "${USE_API:-}" =~ ^[Yy] ]]; then
    echo ">>> 交互式配置 OpenAI 兼容 Agent API（可先用环境变量预填：JUDGE_BASE_URL / JUDGE_API_KEY / JUDGE_MODEL）"
    read -rp "Agent Base URL (默认 https://api.openai.com/v1): " JUDGE_BASE_URL
    JUDGE_BASE_URL="${JUDGE_BASE_URL:-https://api.openai.com/v1}"
    read -rp "API Key (回车则使用环境变量 JUDGE_API_KEY): " JUDGE_API_KEY
    read -rp "Model ID (默认 gpt-4o-mini): " JUDGE_MODEL
    JUDGE_MODEL="${JUDGE_MODEL:-gpt-4o-mini}"
    export JUDGE_BASE_URL JUDGE_API_KEY JUDGE_MODEL
    "$PY" test.py --stage defense --judge api
else
    echo ">>> 离线规则 Agent 模拟器（无需 API，秒级跑通；真实模型请选择 y）"
    "$PY" test.py --stage defense --judge mock
fi
