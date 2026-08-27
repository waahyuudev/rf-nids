# syntax=docker/dockerfile:1
FROM eclipse-temurin:8-jdk-jammy@sha256:e0e0243c25c8985bb786948c2e23d267597ad9751c0311f43c113211a25392f5 AS builder

ARG CICFLOWMETER_REPOSITORY=https://github.com/ahlashkari/CICFlowMeter
ARG CICFLOWMETER_COMMIT=98a5ebad0df579cc8b43eedd3421b3ae87699901
ARG CICFLOWMETER_ARCHIVE_SHA256=fcaf387d0a7ce6a7a0cf88545163e96173569121f16af81d483f8f775de39a22

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl maven unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN curl --fail --location --silent --show-error \
      "${CICFLOWMETER_REPOSITORY}/archive/${CICFLOWMETER_COMMIT}.tar.gz" \
      --output source.tar.gz \
    && echo "${CICFLOWMETER_ARCHIVE_SHA256}  source.tar.gz" | sha256sum --check --strict \
    && mkdir source \
    && tar --extract --gzip --file source.tar.gz --directory source --strip-components=1

WORKDIR /build/source
RUN mvn install:install-file \
      -Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
      -DgroupId=org.jnetpcap \
      -DartifactId=jnetpcap \
      -Dversion=1.4.1 \
      -Dpackaging=jar \
    && chmod 0755 gradlew \
    && ./gradlew --no-daemon installDist \
    && { java -version 2>&1; mvn -version; ./gradlew --version; } > /build/toolchain-versions.txt

FROM eclipse-temurin:8-jre-jammy@sha256:8d8ffe619c1b4aebfa670426ea6b938cccf76faa491ca8483dee520c48b30441 AS runtime

ARG CICFLOWMETER_REPOSITORY=https://github.com/ahlashkari/CICFlowMeter
ARG CICFLOWMETER_COMMIT=98a5ebad0df579cc8b43eedd3421b3ae87699901
ARG CICFLOWMETER_ARCHIVE_SHA256=fcaf387d0a7ce6a7a0cf88545163e96173569121f16af81d483f8f775de39a22

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin cicflowmeter

COPY --from=builder /build/source/build/install/CICFlowMeter /opt/CICFlowMeter
COPY --from=builder /build/toolchain-versions.txt /opt/CICFlowMeter/BUILD_TOOLCHAIN.txt
COPY entrypoint.sh /usr/local/bin/historical-cicflowmeter
RUN chmod 0755 /usr/local/bin/historical-cicflowmeter \
    && mkdir /work \
    && chown cicflowmeter:cicflowmeter /work

LABEL org.opencontainers.image.source="${CICFLOWMETER_REPOSITORY}" \
      org.opencontainers.image.revision="${CICFLOWMETER_COMMIT}" \
      org.opencontainers.image.version="4.0-historical-validation" \
      org.opencontainers.image.description="Pinned Java CICFlowMeter for offline Experiment C compatibility validation" \
      rf_nids.source.archive.sha256="${CICFLOWMETER_ARCHIVE_SHA256}" \
      rf_nids.target.platform="linux/amd64" \
      rf_nids.jnetpcap.version="1.4.1-r1425" \
      rf_nids.gradle.version="4.2"

USER cicflowmeter
WORKDIR /work
ENTRYPOINT ["historical-cicflowmeter"]
