FROM node:12 as builder

WORKDIR /opt/build

COPY package.json yarn.lock ./
RUN yarn

COPY tsconfig.json ./
COPY src src

RUN yarn build

FROM verdaccio/verdaccio:4.10.0

COPY --from=builder /opt/build/package.json /verdaccio/plugins/verdaccio-oidc/package.json

USER root
RUN cd /verdaccio/plugins/verdaccio-oidc && env NODE_ENV=production npm i
USER verdaccio

COPY --from=builder /opt/build/lib /verdaccio/plugins/verdaccio-oidc/lib
