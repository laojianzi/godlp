// Package header defines API information about DLP SDK, including DetectResult, mask methods and API functions.
package header

import (
	"strings"
)

// DetectResult Data Structure. Two kinds of result
// ResultType: VALUE, returned from Detect() and DeIdentify()
// ResultType: KV, returned from DetectMap(), DetectJSON() and DeIdentifyMap()
type DetectResult struct {
	RuleID     int32  `json:"rule_id"`     // RuleID of rules in conf file
	Text       string `json:"text"`        // substring which is detected by rule
	MaskText   string `json:"mask_text"`   // mask string which is de identify by rule
	ResultType string `json:"result_type"` // VALUE or KV, based on Rule
	Key        string `json:"key"`         // In ResultType: KV, Key is key of map for path of json object
	// In ResultType: VALUE mode, DetectResult.Text will be inputText[ByteStart:ByteEnd]
	// In ResultType: KV, DetectResult.Text will be inputMap[DetectResult.Key][ByteStart:ByteEnd]
	ByteStart int `json:"byte_start"`
	ByteEnd   int `json:"byte_end"`
	// fields are defined in conf file
	InfoType  string            `json:"info_type"`
	EnName    string            `json:"en_name"`
	CnName    string            `json:"cn_name"`
	GroupName string            `json:"group_name"`
	Level     string            `json:"level"`
	ExtInfo   map[string]string `json:"ext_info,omitempty"`
}

var (
	ExampleCHAR    = "ExampleCHAR"
	ExampleTAG     = "ExampleTAG"
	ExampleREPLACE = "ExampleREPLACE"
	ExampleEMPTY   = "ExampleEMPTY"
	ExampleBASE64  = "ExampleBASE64"
	NULL           = "NULL"
	CHINAPHONE     = "CHINAPHONE"
	PHONE          = "PHONE"
	CHINAID        = "CHINAID"
	IDCARD         = "IDCARD"
	Email          = "Email"
	UID            = "UID"
	BANK           = "BANK"
	PASSPORT       = "PASSPORT"
	ADDRESS        = "ADDRESS"
	NAME           = "NAME"
	NUMBER         = "NUMBER"
	MACADDR        = "MACADDR"
	ABA            = "ABA"
	BITCOIN        = "BITCOIN"
	CAR            = "CAR"
	DID            = "DID"
	BIRTH          = "BIRTH"
	AGE            = "AGE"
	EDU            = "EDU"
)

type Processor func(rawLog string, kvs ...interface{}) (string, []interface{}, bool)

// EngineAPI is a collection of DLP APIs
type EngineAPI interface {
	// EngineConfAPI conf apis
	EngineConfAPI

	// EngineDetectAPI detect apis
	EngineDetectAPI

	// EngineDeIdentifyAPI de identify apis
	EngineDeIdentifyAPI

	// EngineProcessorAPI processor apis
	EngineProcessorAPI

	// EngineMaskAPI mask apis
	EngineMaskAPI

	// ShowResults print results in console
	// 打印识别结果
	ShowResults(resultArray []*DetectResult)

	// Close engine object, release memory of inner object
	// 关闭，释放内部变量
	Close()

	// GetVersion Get Dlp SDK version string
	// 获取版本号
	GetVersion() string

	// DisableAllRules will disable all rules, only used for benchmark baseline
	// 业务禁止使用
	DisableAllRules() error
}

// EngineConfAPI is a collection of dlp config APIs
type EngineConfAPI interface {
	// ApplyConfig by configuration content
	// 传入conf string 进行配置
	ApplyConfig(conf string) error

	// ApplyConfigFile by config file path
	// 传入filePath 进行配置
	ApplyConfigFile(filePath string) error

	// ShowDlpConf will print config file
	// 打印配置文件
	ShowDlpConf() error

	// GetDefaultConf will return default config string
	// 返回默认的conf string
	GetDefaultConf() string

	// ApplyConfigDefault will use embedded local config, only used for DLP team
	// 业务禁止使用
	ApplyConfigDefault() error
}

// EngineDetectAPI is a collection of dlp detect APIs
type EngineDetectAPI interface {
	// Detect string
	// 对string进行敏感信息识别
	Detect(inputText string) ([]*DetectResult, error)

	// DetectMap detects KV map
	// 对map[string]string进行敏感信息识别
	DetectMap(inputMap map[string]string) ([]*DetectResult, error)

	// DetectJSON detects json string
	// 对json string 进行敏感信息识别
	DetectJSON(jsonText string) ([]*DetectResult, error)
}

// EngineDeIdentifyAPI is a collection of dlp de identify APIs
type EngineDeIdentifyAPI interface {
	// DeIdentifyJSONByResult  returns masked json object in string format from the passed-in []*DetectResult.
	// You may want to call DetectJSON first to obtain the []*DetectResult.
	// 根据传入的 []*DetectResult 对 Json 进行打码，返回打码后的JSON string
	DeIdentifyJSONByResult(jsonText string, detectResults []*DetectResult) (outStr string, retErr error)

	// DeIdentify detects string firstly, then return masked string and results
	// 对string先识别，然后按规则进行打码
	DeIdentify(inputText string) (string, []*DetectResult, error)

	// DeIdentifyMap detects KV map firstly,then return masked map
	// 对map[string]string先识别，然后按规则进行打码
	DeIdentifyMap(inputMap map[string]string) (map[string]string, []*DetectResult, error)

	// DeIdentifyJSON detects JSON firstly, then return masked json object in string format and results
	// 对jsonText先识别，然后按规则进行打码，返回打码后的JSON string
	DeIdentifyJSON(jsonText string) (string, []*DetectResult, error)
}

// EngineProcessorAPI is a collection of dlp processor APIs
type EngineProcessorAPI interface {
	// NewLogProcessor create a log processor for the package logs
	// 日志脱敏处理函数，调用过之后，eng只能用于log处理，因为规则会做专门的优化，不适合其他API使用
	// 最大输入1KB, 16 items, 预计最高200QPS，超出会截断日志，CPU也会相应升高，业务需要特别关注。
	NewLogProcessor() Processor

	// NewEmptyLogProcessor will new a log processor which will do nothing
	// 业务禁止使用
	NewEmptyLogProcessor() Processor
}

// EngineMaskAPI is a collection of dlp mask APIs
type EngineMaskAPI interface {
	// Mask inputText following predefined method of MaskRules in config
	// 根据脱敏规则直接脱敏
	Mask(inputText string, methodName string) (string, error)

	// MaskStruct will mask a struct object by tag mask info
	// 根据tag mask里定义的脱敏规则对struct object直接脱敏，必须传入指针
	MaskStruct(inObj interface{}) (interface{}, error)

	// RegisterMasker Register DIY Masker
	// 注册自定义打码函数
	RegisterMasker(maskName string, maskFunc func(string) (string, error)) error
}

// IsValue checks whether the ResultType is VALUE
func (I *DetectResult) IsValue() bool {
	return strings.Compare(I.ResultType, "VALUE") == 0
}

// IsKV checks whether the ResultType is KV
func (I *DetectResult) IsKV() bool {
	return strings.Compare(I.ResultType, "KV") == 0
}
