package mailer

import (
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

func buildMIME(fromName, fromAddress string, msg Message) []byte {
	var b strings.Builder

	from := mail.Address{Name: fromName, Address: fromAddress}
	b.WriteString("From: " + from.String() + "\r\n")
	b.WriteString("To: " + strings.Join(msg.To, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", msg.Subject) + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + uuid.NewString() + "@" + domainOf(fromAddress) + ">\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	if msg.HTML == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		b.WriteString("\r\n")
		b.WriteString(msg.Text)
		return []byte(b.String())
	}

	boundary := "openiam-" + uuid.NewString()
	b.WriteString(`Content-Type: multipart/alternative; boundary="` + boundary + `"` + "\r\n")
	b.WriteString("\r\n")

	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("\r\n")
	b.WriteString(msg.Text + "\r\n")

	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	b.WriteString("\r\n")
	b.WriteString(msg.HTML + "\r\n")

	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

func domainOf(address string) string {
	if idx := strings.LastIndex(address, "@"); idx >= 0 {
		return address[idx+1:]
	}
	return "openrealm.io"
}

func sender(fromName, fromAddress string) string {
	return fmt.Sprintf("%s <%s>", fromName, fromAddress)
}
