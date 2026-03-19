FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /dnstt-server ./dnstt-server


FROM scratch

COPY --from=builder /dnstt-server /dnstt-server

EXPOSE 53/udp

ENTRYPOINT ["/dnstt-server"]
