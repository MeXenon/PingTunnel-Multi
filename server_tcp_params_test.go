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
