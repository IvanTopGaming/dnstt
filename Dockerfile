FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /dnstt-server ./dnstt-server


FROM scratch AS server

COPY --from=builder /dnstt-server /dnstt-server

EXPOSE 53/udp

# Run as nobody (uid 65534) — no shell, no package manager in scratch image.
USER 65534:65534

ENTRYPOINT ["/dnstt-server"]
