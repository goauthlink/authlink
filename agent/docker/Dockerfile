# Copyright 2025 The AuthLink Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

FROM alpine:3.21 

LABEL org.opencontainers.image.authors="Anton Gubarev <antgubarev.dev@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/goauthlink/authlink"
LABEL org.opencontainers.image.description="high-performance auth service focused on working with HTTP requests"

ARG BIN
ARG TARGETOS
ARG TARGETARCH

COPY dist/${BIN}-${TARGETOS}_${TARGETARCH} /agent

ENV PATH=${PATH}:/

ENTRYPOINT ["/agent"]