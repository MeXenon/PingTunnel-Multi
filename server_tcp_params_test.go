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

func TestServerReplyTokensDefaultToSmallBrowserSafeBurst(t *testing.T) {
	t.Setenv(serverICMPReplyBurstEnv, "")

	server := &Server{replyTokens: make(map[string][]icmpReplyToken)}
	server.queueReplyTokens("client#1", 100, 200)

	for i := 0; i < serverICMPDefaultReplyBurst; i++ {
		token, ok := server.popReplyToken("client#1")
		if !ok {
			t.Fatalf("missing token %d", i)
		}
		if token.id != 100 || token.seq != 200+i {
			t.Fatalf("unexpected token %d: %#v", i, token)
		}
	}
	if _, ok := server.popReplyToken("client#1"); ok {
		t.Fatalf("expected default burst to emit exactly %d tokens", serverICMPDefaultReplyBurst)
	}
}

func TestServerReplyTokensHonorBoundedBurstOverride(t *testing.T) {
	t.Setenv(serverICMPReplyBurstEnv, "3")

	server := &Server{replyTokens: make(map[string][]icmpReplyToken)}
	server.queueReplyTokens("client#1", 7, 9)

	for i := 0; i < 3; i++ {
		token, ok := server.popReplyToken("client#1")
		if !ok {
			t.Fatalf("missing token %d", i)
		}
		if token.id != 7 || token.seq != 9+i {
			t.Fatalf("unexpected token %d: %#v", i, token)
		}
	}
	if _, ok := server.popReplyToken("client#1"); ok {
		t.Fatal("expected exactly three reply tokens")
	}
}

func TestServerReplyTokensAreScopedByClientSession(t *testing.T) {
	t.Setenv(serverICMPReplyBurstEnv, "")

	server := &Server{replyTokens: make(map[string][]icmpReplyToken)}
	server.queueReplyTokens("192.0.2.1#100", 100, 1)
	server.queueReplyTokens("192.0.2.1#200", 200, 1)

	token, ok := server.popReplyToken("192.0.2.1#100")
	if !ok {
		t.Fatal("expected token for first client")
	}
	if token.id != 100 {
		t.Fatalf("token leaked across echo ids: %#v", token)
	}

	token, ok = server.popReplyToken("192.0.2.1#200")
	if !ok {
		t.Fatal("expected token for second client")
	}
	if token.id != 200 {
		t.Fatalf("token leaked across echo ids: %#v", token)
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

func TestPrioritizeServerFramesDoesNotTreatHeartbeatAsPayload(t *testing.T) {
	frames := list.New()
	frames.PushBack(&network.Frame{Type: int32(network.Frame_DATA), Data: &network.FrameData{Type: int32(network.FrameData_HB)}})
	frames.PushBack(&network.Frame{Type: int32(network.Frame_ACK)})
	frames.PushBack(&network.Frame{Type: int32(network.Frame_DATA), Data: &network.FrameData{Type: int32(network.FrameData_USER_DATA), Data: []byte("payload")}})

	ordered := prioritizeServerFrames(frames)
	if len(ordered) != 3 {
		t.Fatalf("unexpected frame count: %d", len(ordered))
	}
	if ordered[0].Data == nil || ordered[0].Data.Type != int32(network.FrameData_USER_DATA) {
		t.Fatalf("first frame should be user payload, got %#v", ordered[0])
	}
	if ordered[2].Data == nil || ordered[2].Data.Type != int32(network.FrameData_HB) {
		t.Fatalf("heartbeat should be delayed behind payload and ack, got %#v", ordered[2])
	}
}
