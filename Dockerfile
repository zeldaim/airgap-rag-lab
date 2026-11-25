FROM python:3.12-slim
WORKDIR /app
COPY llm ./llm
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python"]
CMD ["llm/client.py"]
