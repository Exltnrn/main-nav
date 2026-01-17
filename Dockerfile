FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o main-nav .

FROM alpine:latest

WORKDIR /app

RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /app/main-nav .
COPY templates/ templates/
COPY static/ static/

VOLUME ["/app/data"]

EXPOSE 8080

CMD ["./main-nav"]
