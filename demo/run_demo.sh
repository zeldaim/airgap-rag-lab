#!/usr/bin/env bash
# 전 과정을 순서대로 돌리고 실제 출력을 docs/evidence/ 에 그대로 저장한다 (로그 = 증거).
#   bash demo/run_demo.sh              # 빠른 단계들 (LLM 호출 3회, 약 3~4분)
#   bash demo/run_demo.sh --with-eval  # + 트리아지 A/B 평가(LLM 24회, 15~20분)
# 사전 조건: docker compose up -d --build 가능, ollama_models 볼륨에 qwen2.5:7b-instruct 와 bge-m3 가 있을 것.
set -u
cd "$(dirname "$0")/.."
OUT=docs/evidence
mkdir -p "$OUT"

run() {  # run <파일이름> <명령...> : 첫 줄에 명령, 이어서 실제 출력(Compose 의 생성 알림 줄은 뺀다)
  local name=$1; shift
  { echo "\$ $*"; echo "# $(date '+%Y-%m-%d %H:%M:%S')  commit $(git rev-parse --short HEAD)"; echo; } > "$OUT/$name.txt"
  "$@" 2>&1 | grep -v -E '^ (Volume|Network|Container) ' >> "$OUT/$name.txt"
  echo "saved $OUT/$name.txt"
}
APP="docker compose run --rm app"

run 00_env $APP rag/env_check.py
run 01_airgap_verify $APP llm/verify_airgap.py
run 02_ingest $APP rag/ingest.py
run 03_retrieval_eval $APP rag/eval.py -v
run 04_facts_check $APP rag/facts_check.py
run 05_ask $APP rag/ask.py -k 3 "같은 IP가 120초 안에 서로 다른 객체 ID 10개를 성공적으로 조회하면 어떤 룰이 울리고 레벨은 몇이야?"
run 06_triage_with_facts $APP rag/triage.py samples/triage_eval.jsonl -n 0 --show-prompt
run 07_triage_without_facts $APP rag/triage.py samples/triage_eval.jsonl -n 0 --no-facts --show-prompt
run 08_triage_false_positive $APP rag/triage.py samples/triage_eval.jsonl -n 8
if [ "${1:-}" = "--with-eval" ]; then
  run 09_triage_eval $APP rag/triage_eval.py samples/triage_eval.jsonl
fi
echo "끝. 결과: $OUT/"
