FROM python:3.12-slim
RUN pip install --no-cache-dir opencanary
COPY opencanary.conf /etc/opencanaryd/opencanary.conf
CMD ["opencanaryd", "--dev"]
