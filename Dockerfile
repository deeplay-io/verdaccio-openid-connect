ARG VERDACCIO_VERSION=5.31.0
FROM verdaccio/verdaccio:${VERDACCIO_VERSION} as base

FROM base as builder
USER root
WORKDIR /opt/build

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src src
RUN npm run build

FROM base as final

COPY --from=builder --chown=verdaccio:verdaccio /opt/build/package.json /verdaccio/plugins/verdaccio-openid-connect/package.json

USER root
RUN cd /verdaccio/plugins/verdaccio-openid-connect && env NODE_ENV=production npm i
USER verdaccio

COPY --from=builder /opt/build/lib /verdaccio/plugins/verdaccio-openid-connect/lib
