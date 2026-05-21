package pingtunnel

import "testing"

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
