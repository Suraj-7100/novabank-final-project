FROM golang:1.26-alpine AS build
# Let Go download a newer toolchain if a dependency asks for one.
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
ENV GIN_MODE=release PORT=8080
EXPOSE 8080
ENTRYPOINT ["/api"]
