# Explicit free demonstration image. Production Containerfiles and policies are unchanged.
FROM node@sha256:3e69116c924bfcba6c6979aff60d966c37aef56d488ce091c69d442ebec9f103 AS node
FROM eclipse-temurin@sha256:2feab631bffce6236d8bb5261a4abe19a8d6f85bad1c01166f74686c983d011f AS build
WORKDIR /source
COPY . .
RUN chmod +x gradlew && ./gradlew --no-daemon --max-workers=1 \
    -Dorg.gradle.jvmargs="-Xmx768m -XX:MaxMetaspaceSize=384m" \
    :apps:edge-gateway:installDist

FROM eclipse-temurin@sha256:2feab631bffce6236d8bb5261a4abe19a8d6f85bad1c01166f74686c983d011f
WORKDIR /opt/elmpay
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=build --chown=10001:10001 /source/apps/edge-gateway/build/install/edge-gateway/ apps/edge-gateway/build/install/edge-gateway/
COPY --chown=10001:10001 apps/checkout-web/ apps/checkout-web/
COPY --chown=10001:10001 apps/free-demo/src/ apps/free-demo/src/
USER 10001:10001
ENV NODE_ENV=production
EXPOSE 10000
CMD ["node", "--max-old-space-size=64", "apps/free-demo/src/start.mjs"]
