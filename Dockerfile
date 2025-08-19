FROM golang:1.21

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o vt_server cmd/server/main.go

CMD ["./vt_server", "--addr", ":8000", "--cert", "cert.pem", "--key", "key.pem"]