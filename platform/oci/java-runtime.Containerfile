ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG APP_DIRECTORY
ARG MAIN_CLASS_FILE
ARG MAIN_CLASS_ALLOWLIST
ARG SOURCE_COMMIT
ARG PRODUCT_IMAGE_MANIFEST_DIGEST

RUN mkdir -p /opt/elmpay/bin /opt/elmpay/etc \
    && chown 10001:10001 /opt/elmpay/bin /opt/elmpay/etc \
    && chmod 0555 /opt/elmpay/bin /opt/elmpay/etc

COPY --chown=10001:10001 ${APP_DIRECTORY}/ /opt/elmpay/app/
COPY --chown=10001:10001 --chmod=0555 platform/oci/java-main /opt/elmpay/bin/java-main
COPY --chown=10001:10001 --chmod=0444 ${MAIN_CLASS_FILE} /opt/elmpay/etc/default-main-class
COPY --chown=10001:10001 --chmod=0444 ${MAIN_CLASS_ALLOWLIST} /opt/elmpay/etc/allowed-main-classes

LABEL org.opencontainers.image.source="https://github.com/zpcaiai/elmpay" \
      org.opencontainers.image.revision="${SOURCE_COMMIT}" \
      io.elmpay.product-image-manifest-digest="${PRODUCT_IMAGE_MANIFEST_DIGEST}"

USER 10001:10001
WORKDIR /opt/elmpay
ENTRYPOINT ["/opt/elmpay/bin/java-main"]
