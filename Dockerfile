FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o /app/server ./main.go

FROM scratch

WORKDIR /app

COPY --from=builder /app/server /app/server

EXPOSE 3000

ENTRYPOINT ["/app/server"]
