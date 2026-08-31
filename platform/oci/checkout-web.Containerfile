ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG SOURCE_COMMIT
ARG PRODUCT_IMAGE_MANIFEST_DIGEST

COPY --chown=10001:10001 apps/checkout-web/package.json /opt/elmpay/app/package.json
COPY --chown=10001:10001 apps/checkout-web/src/ /opt/elmpay/app/src/
COPY --chown=10001:10001 apps/checkout-web/public/ /opt/elmpay/app/public/
COPY --chown=10001:10001 apps/checkout-web/security/ /opt/elmpay/app/security/

LABEL org.opencontainers.image.source="https://github.com/zpcaiai/elmpay" \
      org.opencontainers.image.revision="${SOURCE_COMMIT}" \
      io.elmpay.product-image-manifest-digest="${PRODUCT_IMAGE_MANIFEST_DIGEST}"

USER 10001:10001
WORKDIR /opt/elmpay/app
ENTRYPOINT ["/usr/local/bin/node", "src/server.mjs"]
