FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/minimal-waf ./cmd/minimal-waf

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/minimal-waf /minimal-waf
USER 65532:65532
EXPOSE 8081
ENTRYPOINT ["/minimal-waf"]
CMD ["-config", "/etc/minimal-waf/config.json"]
