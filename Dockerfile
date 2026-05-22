FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/oidc-proxy .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/oidc-proxy /oidc-proxy
EXPOSE 8080
ENTRYPOINT ["/oidc-proxy"]
