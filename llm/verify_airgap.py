#!/usr/bin/env python3
"""망분리 재현이 진짜인지 확인 — (1) 로컬 LLM 호출은 되고 (2) 외부 인터넷 접속은 물리적으로 안 되는지 둘 다 본다.
docker-compose.yml 의 `airgap` 네트워크(internal: true)가 실제로 격리하는지 증거로 남기는 스크립트.

  python llm/verify_airgap.py   (docker compose run --rm app python llm/verify_airgap.py 로 실행)
"""
import socket
import sys

from client import generate


def check_local_llm() -> bool:
    try:
        reply = generate("1+1은? 숫자로만 답해.")
        print(f"[로컬 LLM] 응답 받음: {reply!r}")
        return bool(reply.strip())
    except Exception as e:
        print(f"[로컬 LLM] 실패: {e}")
        return False


def check_no_internet() -> bool:
    """공개 DNS(8.8.8.8:443)에 연결을 시도한다 — internal 네트워크면 반드시 실패해야 한다."""
    try:
        with socket.create_connection(("8.8.8.8", 443), timeout=5):
            print("[망분리] 외부 접속이 **됐다** — internal 네트워크가 아니거나 설정이 샜다")
            return False
    except OSError as e:
        print(f"[망분리] 외부 접속 시도 → 예상대로 실패: {e}")
        return True


def main():
    ok_llm = check_local_llm()
    ok_airgap = check_no_internet()
    print(f"\n로컬 LLM 동작: {'OK' if ok_llm else 'FAIL'} · 외부 차단: {'OK' if ok_airgap else 'FAIL'}")
    return 0 if (ok_llm and ok_airgap) else 1


if __name__ == "__main__":
    sys.exit(main())
