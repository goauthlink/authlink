# Copyright 2024 The AuthLink Authors.  All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

FROM alpine:3.21 

WORKDIR /authlink

ARG AGENT_BIN

COPY dist/${AGENT_BIN} /authlink/agent

ENV PATH=${PATH}:/authlink

ENTRYPOINT ["agent"]