# syntax=docker/dockerfile:1
FROM eclipse-temurin:8-jdk-jammy@sha256:e0e0243c25c8985bb786948c2e23d267597ad9751c0311f43c113211a25392f5 AS builder

ARG CICFLOWMETER_REPOSITORY=https://github.com/ahlashkari/CICFlowMeter
ARG CICFLOWMETER_COMMIT=a26aae27f21d165ff30b4b28e75124a5f9b4b2c4
ARG CICFLOWMETER_ARCHIVE_SHA256=78f13b2d474e5a669a367aef610d597cf86bc338088ffdd72228671bdca364c7

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
# V3 ships a headless offline CLI in CICFlowMeter.java but excludes it from the
# Gradle source set. Include that exact upstream file without changing its bytes
# or importing the later V4 Cmd implementation.
RUN sed -i "/exclude '\*\*\/CICFlowMeter.java'/d" build.gradle \
    && mvn install:install-file \
      -Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
      -DgroupId=org.jnetpcap \
      -DartifactId=jnetpcap \
      -Dversion=1.4.1 \
      -Dpackaging=jar \
    && chmod 0755 gradlew \
    && ./gradlew --no-daemon installDist \
    && { java -version 2>&1; mvn -version; ./gradlew --version; } > /build/toolchain-versions.txt \
    && sha256sum \
      src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java \
      src/main/java/cic/cs/unb/ca/jnetpcap/BasicPacketInfo.java \
      src/main/java/cic/cs/unb/ca/jnetpcap/FlowFeature.java \
      src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java \
      src/main/java/cic/cs/unb/ca/flow/FlowMgr.java \
      src/main/java/cic/cs/unb/ca/ifm/CICFlowMeter.java \
      > /build/source-hashes.txt

FROM eclipse-temurin:8-jre-jammy@sha256:8d8ffe619c1b4aebfa670426ea6b938cccf76faa491ca8483dee520c48b30441 AS runtime

ARG CICFLOWMETER_REPOSITORY=https://github.com/ahlashkari/CICFlowMeter
ARG CICFLOWMETER_COMMIT=a26aae27f21d165ff30b4b28e75124a5f9b4b2c4
ARG CICFLOWMETER_ARCHIVE_SHA256=78f13b2d474e5a669a367aef610d597cf86bc338088ffdd72228671bdca364c7

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin cicflowmeter

COPY --from=builder /build/source/build/install/CICFlowMeter /opt/CICFlowMeter
COPY --from=builder /build/toolchain-versions.txt /opt/CICFlowMeter/BUILD_TOOLCHAIN.txt
COPY --from=builder /build/source-hashes.txt /opt/CICFlowMeter/SOURCE_HASHES.txt
COPY entrypoint.sh /usr/local/bin/cicflowmeter-v3
RUN chmod 0755 /usr/local/bin/cicflowmeter-v3 \
    && mkdir /work \
    && chown cicflowmeter:cicflowmeter /work

LABEL org.opencontainers.image.source="${CICFLOWMETER_REPOSITORY}" \
      org.opencontainers.image.revision="${CICFLOWMETER_COMMIT}" \
      org.opencontainers.image.version="3.0-experiment-c" \
      org.opencontainers.image.description="Pinned official CICFlowMeter V3 for isolated offline Experiment C validation" \
      rf_nids.source.archive.sha256="${CICFLOWMETER_ARCHIVE_SHA256}" \
      rf_nids.target.platform="linux/amd64" \
      rf_nids.jnetpcap.version="1.4.1-r1425" \
      rf_nids.gradle.version="4.2" \
      rf_nids.cli="upstream CICFlowMeter.java included by removing its build exclusion"

USER cicflowmeter
WORKDIR /work
ENTRYPOINT ["cicflowmeter-v3"]
