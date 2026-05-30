FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agp ./cmd/agp

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /
COPY --from=build /out/agp /usr/local/bin/agp
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agp"]
