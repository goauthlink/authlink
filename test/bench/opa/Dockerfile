# Copyright 2025 The AuthLink Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

FROM alpine:3.20 

ARG TARGETOS
ARG TARGETARCH

RUN apk add --update curl && \
    rm -rf /var/cache/apk/*

RUN curl https://github.com/open-policy-agent/opa-envoy-plugin/releases/download/v0.70.0-envoy-1/opa_envoy_${TARGETOS}_${TARGETARCH}_static -O -L \ 
    && mv opa_envoy_${TARGETOS}_${TARGETARCH}_static /opa \
    && chmod +x /opa

ENTRYPOINT ["/opa"]
CMD ["run"]