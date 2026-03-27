FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /adobe-sign .

FROM alpine:3.21
RUN apk add --no-cache curl sed
COPY --from=builder /adobe-sign /usr/local/bin/adobe-sign
ENTRYPOINT ["adobe-sign"]
