FROM python:3.12-slim
RUN pip install --no-cache-dir opencanary
RUN mkdir -p /etc/opencanaryd /var/tmp/opencanary
COPY opencanary.conf /etc/opencanaryd/opencanary.conf
COPY opencanary.conf /root/.opencanary.conf
CMD ["sh", "-c", "cp /etc/opencanaryd/opencanary.conf /root/.opencanary.conf && touch /var/tmp/opencanary/opencanary.log && exec opencanaryd --dev"]
