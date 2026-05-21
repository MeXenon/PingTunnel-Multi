package loggo

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	LEVEL_DEBUG = iota
	LEVEL_INFO
	LEVEL_WARN
	LEVEL_ERROR
)

type Config struct {
	Level      int
	Prefix     string
	MaxDay     int
	NoLogFile  bool
	NoPrint    bool
	NoLogColor bool
	FullPath   bool
	printer    io.Writer
}

var (
	gConfig = Config{Level: LEVEL_DEBUG, Prefix: "pingtunnel", MaxDay: 1, NoLogFile: true}
	gMu     sync.Mutex
)

func Ini(config Config) {
	gMu.Lock()
	defer gMu.Unlock()
	if strings.TrimSpace(config.Prefix) == "" {
		config.Prefix = "pingtunnel"
	}
	if config.MaxDay <= 0 {
		config.MaxDay = 1
	}
	gConfig = config
}

func SetPrinter(w io.Writer) {
	gMu.Lock()
	gConfig.printer = w
	gMu.Unlock()
}

func Debug(format string, a ...interface{}) { write(LEVEL_DEBUG, format, a...) }
func Info(format string, a ...interface{})  { write(LEVEL_INFO, format, a...) }
func Warn(format string, a ...interface{})  { write(LEVEL_WARN, format, a...) }
func Error(format string, a ...interface{}) { write(LEVEL_ERROR, format, a...) }

func NameToLevel(name string) int {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "DEBUG":
		return LEVEL_DEBUG
	case "INFO":
		return LEVEL_INFO
	case "WARN", "WARNING":
		return LEVEL_WARN
	case "ERROR":
		return LEVEL_ERROR
	default:
		return -1
	}
}

func levelName(level int) string {
	switch level {
	case LEVEL_DEBUG:
		return "DEBUG"
	case LEVEL_INFO:
		return "INFO"
	case LEVEL_WARN:
		return "WARN"
	case LEVEL_ERROR:
		return "ERROR"
	default:
		return "INFO"
	}
}

func write(level int, format string, a ...interface{}) {
	gMu.Lock()
	cfg := gConfig
	gMu.Unlock()
	if cfg.Level > level {
		return
	}

	line := fmt.Sprintf("[%s] [%s] %s\n", levelName(level), time.Now().Format(time.RFC3339Nano), fmt.Sprintf(format, a...))
	if !cfg.NoLogFile {
		writeFile(cfg, level, line)
	}
	if cfg.NoPrint {
		return
	}
	if cfg.printer != nil {
		_, _ = cfg.printer.Write([]byte(line))
		return
	}
	fmt.Print(line)
}

func writeFile(cfg Config, level int, line string) {
	name := strings.TrimSpace(cfg.Prefix)
	if name == "" {
		name = "pingtunnel"
	}
	filename := fmt.Sprintf("%s.%s", name, strings.ToLower(levelName(level)))
	path := filename
	if cfg.FullPath {
		path = filepath.Clean(filename)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.WriteString(line)
}
