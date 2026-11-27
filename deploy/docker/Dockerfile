FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agp ./cmd/agp
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agpctl ./cmd/agpctl
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agp-security-journal ./cmd/agp-security-journal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agp-edge-auth ./cmd/agp-edge-auth

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /
COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agp"]
