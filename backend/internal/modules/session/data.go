package session

import "time"

type Data struct {
	id        string
	userID    uint64
	publicID  string
	csrf      string
	createdAt time.Time
}

func NewData(id string, userID uint64, publicID, csrf string, createdAt time.Time) *Data {
	return &Data{
		id:        id,
		userID:    userID,
		publicID:  publicID,
		csrf:      csrf,
		createdAt: createdAt,
	}
}

func (d *Data) ID() string           { return d.id }
func (d *Data) UserID() uint64       { return d.userID }
func (d *Data) PublicID() string     { return d.publicID }
func (d *Data) CSRFToken() string    { return d.csrf }
func (d *Data) CreatedAt() time.Time { return d.createdAt }
