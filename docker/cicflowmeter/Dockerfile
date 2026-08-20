FROM python:3.12-slim

ARG CICFLOWMETER_VERSION=0.4.2

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libpcap-dev tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "cicflowmeter==${CICFLOWMETER_VERSION}"

COPY entrypoint.sh /usr/local/bin/rf-nids-cicflowmeter
RUN chmod 0755 /usr/local/bin/rf-nids-cicflowmeter

ENTRYPOINT ["rf-nids-cicflowmeter"]
