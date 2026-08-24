package notify

import (
	"context"
	"log/slog"
)

// LogSender prints codes instead of sending them. Development only — it is
// wired only when DEV is set and SMTP is unconfigured.
type LogSender struct{ Log *slog.Logger }

func (s LogSender) SendCode(ctx context.Context, to Address, p Purpose, code string) error {
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	log.WarnContext(ctx, "notify: dev sender, code not actually delivered",
		"to", to.Value, "purpose", string(p), "code", code)
	return nil
}
