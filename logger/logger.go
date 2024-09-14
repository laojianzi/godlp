package logger

// Level 是日志级别的标识，级别越高说明日志越重要
type Level int

// 常见的日志级别
const (
	LevelDebug Level = -4
	LevelInfo  Level = 0
	LevelWarn  Level = 4
	LevelError Level = 8
)

// Logger 是日志的常见行为定义
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	SetLevel(level Level)
}

var engine Logger = &defaultLogger{}

// SetLogger 自定义 Logger 输出
func SetLogger(logger Logger) {
	engine = logger
}

// Debugf 会格式化日志内容并输出为 LevelDebug 级别
func Debugf(format string, args ...interface{}) {
	engine.Debugf(format, args)
}

// Infof 会格式化日志内容并输出为 LevelInfo 级别
func Infof(format string, args ...interface{}) {
	engine.Infof(format, args)
}

// Warnf 会格式化日志内容并输出为 LevelWarn 级别
func Warnf(format string, args ...interface{}) {
	engine.Warnf(format, args)
}

// Errorf 会格式化日志内容并输出为 LevelError 级别
func Errorf(format string, args ...interface{}) {
	engine.Errorf(format, args)
}

// SetLevel 用于控制日志输出等级，低于设置的等级的日志不会被输出
func SetLevel(level Level) {
	engine.SetLevel(level)
}
