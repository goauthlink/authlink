FROM golang:1.22.5@sha256:86a3c48a61915a8c62c0e1d7594730399caa3feb73655dfe96c7bc17710e96cf AS build
WORKDIR /apc

COPY . /apc/
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/apc -ldflags="-w -s" -v github.com/auth-policy-controller/apc

FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5 AS final
COPY --from=build /go/bin/apc /bin/apc 

ENTRYPOINT ["apc"]