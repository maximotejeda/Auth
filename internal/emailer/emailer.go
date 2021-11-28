package emailer

import (
	"log"
	"os"
	"strconv"

	"github.com/xhit/go-simple-mail/v2"
)

type Emailer struct {
	Emails  []string
	Copys   []string
	Subject string
	Content string
}

var (
	smtpHost     string = os.Getenv("DEVSMTPHOST")
	smtpPort     string = os.Getenv("DEVSMTPPORT")
	smtpUserName string = os.Getenv("DEVSMTPUSERNAME")
	smtpPassword string = os.Getenv("DEVSMTPPASSWORD")
	smtpEmail    string = os.Getenv("DEVSMTPEMAIL")
)

func SendMail(datos Emailer) {
	server := mail.NewSMTPClient()

	//smtpServer
	// 465 Usa SSL => tarda 1 segundo
	// 587 usa TLS => tarda 4 segundos
	port, _ := strconv.Atoi(smtpPort)
	server.Host = smtpHost
	server.Port = port
	server.Username = smtpUserName
	server.Password = smtpPassword
	server.Encryption = mail.EncryptionTLS

	smtpClient, err := server.Connect()
	if err != nil {
		log.Fatal(err)
	}

	// Create email
	email := mail.NewMSG()
	email.SetFrom("From Me <" + smtpEmail + ">")
	email.AddTo(datos.Emails...)
	email.AddCc(datos.Copys...)
	email.SetSubject(datos.Subject)

	email.SetBody(mail.TextHTML, datos.Content)
	//email.AddAttachment("super_cool_file.png")

	// Send email
	err = email.Send(smtpClient)
	if err != nil {
		log.Print(err)
	}

}
