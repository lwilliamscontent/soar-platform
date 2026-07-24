FROM python:3.13.5-slim@sha256:4c2cf9917bd1cbacc5e9b07320025bdb7cdf2df7b0ceaccb55e9dd7e30987419

RUN useradd --create-home --uid 10001 soar && mkdir /data && chown soar:soar /data
WORKDIR /app
COPY --chown=soar:soar app.py /app/app.py
USER 10001
EXPOSE 8080
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_PATH=/data/soar.db
CMD ["python", "/app/app.py"]
