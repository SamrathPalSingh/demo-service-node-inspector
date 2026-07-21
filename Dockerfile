FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd/node-inspector ./cmd/node-inspector
RUN CGO_ENABLED=0 go build -o /out/node-inspector ./cmd/node-inspector

FROM alpine:3.22
RUN apk add --no-cache util-linux
COPY --from=build /out/node-inspector /node-inspector
USER 0
ENTRYPOINT ["/node-inspector"]
