FROM python:3.12-alpine
RUN apk add --no-cache tcpdump
WORKDIR /srv/firmsight-sinkhole
COPY sinkhole.py .
EXPOSE 53/udp 80/tcp 443/tcp
CMD ["python", "-u", "sinkhole.py"]
