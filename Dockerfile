FROM python:3.12-slim
WORKDIR /app
# 빌드 시점에만 인터넷을 쓴다(패키지 설치). 실행은 internal 네트워크에서만 — docker-compose.yml 참고
RUN pip install --no-cache-dir "chromadb>=1.0,<2"
COPY llm ./llm
COPY rag ./rag
COPY corpus ./corpus
ENV PYTHONUNBUFFERED=1 CHROMA_DIR=/data/chroma ANONYMIZED_TELEMETRY=False
ENTRYPOINT ["python"]
CMD ["llm/client.py"]
