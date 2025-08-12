# syntax=docker/dockerfile:1

FROM python:3.11-slim-bookworm

WORKDIR /app
VOLUME ["/cfg", "/log", "/rec"]

COPY src src/
COPY setup.py setup.cfg ./

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ffmpeg \
        build-essential \
        python3-dev \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir -e . && \
    pip install bili_ticket_gt_python && \
    apt-get purge -y --auto-remove build-essential python3-dev pkg-config libssl-dev
# ref: https://github.com/docker-library/python/issues/60#issuecomment-134322383

ENV BLREC_DEFAULT_SETTINGS_FILE=/cfg/settings.toml
ENV BLREC_DEFAULT_LOG_DIR=/log
ENV BLREC_DEFAULT_OUT_DIR=/rec
ENV TZ="Asia/Shanghai"

EXPOSE 2233
ENTRYPOINT ["blrec", "--host", "0.0.0.0", "--no-progress"]
CMD []
