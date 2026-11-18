# syntax=docker/dockerfile:1
# Optimised Keycloak image (official quay.io/keycloak/keycloak, pinned).
# Valid as both Dockerfile and Containerfile (Docker and Podman).
# Build args let you bump the version without editing this file.
ARG KC_IMAGE_TAG=26.8.2

# ---- Build stage: bake build-time options (DB vendor, health, metrics, theme) ----
FROM quay.io/keycloak/keycloak:${KC_IMAGE_TAG} AS builder
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true
WORKDIR /opt/keycloak
COPY --chown=1000:0 themes/demo /opt/keycloak/themes/demo
RUN /opt/keycloak/bin/kc.sh build

# ---- Runtime stage: optimised, fast-starting server ----
FROM quay.io/keycloak/keycloak:${KC_IMAGE_TAG}
COPY --from=builder --chown=1000:0 /opt/keycloak/ /opt/keycloak/
# Demo realm; ${PLACEHOLDERS} are resolved from environment variables at import time.
COPY --chown=1000:0 realm/demo-realm.json /opt/keycloak/data/import/demo-realm.json
USER 1000
EXPOSE 8080 9000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized", "--import-realm"]
