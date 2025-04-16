FROM golang:1.24.2 AS build

WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o agevault .

FROM scratch

WORKDIR /tmp
COPY --from=build /src/agevault /app/agevault
ENTRYPOINT ["/app/agevault"]
