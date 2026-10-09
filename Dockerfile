FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/identity-sync .

FROM alpine:3.20
RUN addgroup -S app && adduser -S -G app app && apk add --no-cache ca-certificates
COPY --from=build /out/identity-sync /identity-sync
USER app
ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/identity-sync"]
