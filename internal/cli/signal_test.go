package cli

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// The signal handling of Main is released as soon as the first signal
// cancels the context, so a second Ctrl-C terminates the process.
func TestInterruptContextReleasesSignalsAfterFirst(t *testing.T) {
	var stopped atomic.Int32
	var fire context.CancelFunc
	notify := func(parent context.Context, sigs ...os.Signal) (context.Context, context.CancelFunc) {
		ctx, cancel := context.WithCancel(parent)
		fire = cancel
		return ctx, func() { stopped.Add(1); cancel() }
	}
	ctx, stop := interruptContext(notify)
	defer stop()
	time.Sleep(10 * time.Millisecond)
	if stopped.Load() != 0 {
		t.Fatal("signal handling released before any signal")
	}
	fire() // the first signal
	<-ctx.Done()
	deadline := time.Now().Add(2 * time.Second)
	for stopped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stopped.Load() == 0 {
		t.Error("signal handling still registered after the first signal")
	}
}
