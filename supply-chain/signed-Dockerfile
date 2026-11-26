# 태그가 아니라 다이제스트로 고정 (python:3.12-slim, 2026-11-26 기준). 바꿀 때는 supply-chain/README.md 의 갱신 절차를 따른다
FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b
WORKDIR /app
# 빌드 시점에만 인터넷을 쓴다(패키지 설치). 실행은 internal 네트워크에서만 — docker-compose.yml 참고
COPY requirements.lock .
# 해시까지 고정한 잠금 파일 — 해시가 하나라도 다르면 설치가 실패한다 (requirements.in → pip-compile --generate-hashes)
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY llm ./llm
COPY rag ./rag
COPY corpus ./corpus
ENV PYTHONUNBUFFERED=1 CHROMA_DIR=/data/chroma ANONYMIZED_TELEMETRY=False
ENTRYPOINT ["python"]
CMD ["llm/client.py"]
