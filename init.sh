# Iniciador de la aplicacion

export $(grep -v '^#' .env | xargs)
go run "cmd/main.go"
