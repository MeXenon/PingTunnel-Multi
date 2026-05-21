package pingtunnel

import (
	"container/list"
	"testing"

	"github.com/esrrhs/gohome/network"
)

func TestSanitizeServerTCPParamsClampsMobileUnsafeDefaults(t *testing.T) {
	t.Setenv(serverTCPMaxWindowEnv, "")
	t.Setenv(serverTCPMinResendMillisEnv, "")

	bufferSize, windowSize, resendMillis := sanitizeServerTCPParams(1024*1024, 20000, 400)

	if bufferSize != 1024*1024 {
		t.Fatalf("buffer size changed: got %d", bufferSize)
	}
	if windowSize != serverTCPDefaultMaxWindow {
		t.Fatalf("window was not clamped: got %d", windowSize)
	}
	if resendMillis != serverTCPDefaultMinResendMillis {
		t.Fatalf("resend interval was not raised: got %d", resendMillis)
	}
}

func TestSanitizeServerTCPParamsKeepsSaferClientValues(t *testing.T) {
	t.Setenv(serverTCPMaxWindowEnv, "")
	t.Setenv(serverTCPMinResendMillisEnv, "")

	bufferSize, windowSize, resendMillis := sanitizeServerTCPParams(4096, 32, 1500)

	if bufferSize != 4096 {
		t.Fatalf("buffer size changed: got %d", bufferSize)
	}
	if windowSize != 32 {
		t.Fatalf("window changed: got %d", windowSize)
	}
	if resendMillis != 1500 {
		t.Fatalf("resend interval changed: got %d", resendMillis)
	}
}

func TestSanitizeServerTCPParamsHonorsServerOverrides(t *testing.T) {
	t.Setenv(serverTCPMaxWindowEnv, "512")
	t.Setenv(serverTCPMinResendMillisEnv, "600")

	_, windowSize, resendMillis := sanitizeServerTCPParams(0, 20000, 400)

	if windowSize != 512 {
		t.Fatalf("server window override was not applied: got %d", windowSize)
	}
	if resendMillis != 600 {
		t.Fatalf("server resend override was not applied: got %d", resendMillis)
	}
}

func TestServerReplyTokensDefaultToOneReplyPerClientPacket(t *testing.T) {
	t.Setenv(serverICMPReplyBurstEnv, "")

	conn := &ServerConn{}
	conn.queueReplyTokens(100, 200)

	token, ok := conn.popReplyToken()
	if !ok {
		t.Fatal("expected one reply token")
	}
	if token.id != 100 || token.seq != 200 {
		t.Fatalf("unexpected token: %#v", token)
	}
	if _, ok := conn.popReplyToken(); ok {
		t.Fatal("expected default mobile-safe burst to emit one token")
	}
}

func TestServerReplyTokensHonorBoundedBurstOverride(t *testing.T) {
	t.Setenv(serverICMPReplyBurstEnv, "3")

	conn := &ServerConn{}
	conn.queueReplyTokens(7, 9)

	for i := 0; i < 3; i++ {
		token, ok := conn.popReplyToken()
		if !ok {
			t.Fatalf("missing token %d", i)
		}
		if token.id != 7 || token.seq != 9 {
			t.Fatalf("unexpected token %d: %#v", i, token)
		}
	}
	if _, ok := conn.popReplyToken(); ok {
		t.Fatal("expected exactly three reply tokens")
	}
}

func TestPrioritizeServerFramesSendsPayloadBeforePureAck(t *testing.T) {
	frames := list.New()
	frames.PushBack(&network.Frame{Type: int32(network.Frame_ACK)})
	frames.PushBack(&network.Frame{Type: int32(network.Frame_DATA), Data: &network.FrameData{Type: int32(network.FrameData_USER_DATA)}})
	frames.PushBack(&network.Frame{Type: int32(network.Frame_ACK)})

	ordered := prioritizeServerFrames(frames)
	if len(ordered) != 3 {
		t.Fatalf("unexpected frame count: %d", len(ordered))
	}
	if ordered[0].Type != int32(network.Frame_DATA) {
		t.Fatalf("first reply should carry payload/control data, got type %d", ordered[0].Type)
	}
}
