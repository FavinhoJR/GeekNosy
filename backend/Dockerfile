FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY policy ./policy

RUN mkdir -p /app/data

RUN addgroup --system geeknosy && adduser --system --ingroup geeknosy geeknosy \
    && chown -R geeknosy:geeknosy /app

ENV GEEKNOSY_DATABASE_URL=sqlite+aiosqlite:////app/data/geeknosy.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

USER geeknosy

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
