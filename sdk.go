// Package dlp provides dlp sdk api implementation
package dlp

import (
	_ "embed"
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"gopkg.in/yaml.v2"

	"github.com/laojianzi/godlp/conf"
	"github.com/laojianzi/godlp/detector"
	"github.com/laojianzi/godlp/header"
	"github.com/laojianzi/godlp/internal/json"
	"github.com/laojianzi/godlp/logger"
	"github.com/laojianzi/godlp/mask"
)

// DefConf saves the content of conf.yaml
//
//go:embed conf.yml
var DefConf string

// const var for dlp
// outer const values
const (
	Version     = "v1.2.15"
	PackageName = "github.com/laojianzi/godlp"
	FullVer     = PackageName + "@" + Version
)

// const var for default values
const (
	DefMaxInput      = 1024 * 1024                      // 1MB, the getMax input string length
	DefLimitError    = "<--[DLP] Log Limit Exceeded-->" // append to log if limit is exceeded
	DefMaxLogItem    = 16                               // getMax input items for log
	DefResultSize    = 4                                // default results size for array allocation
	DefLineBlockSize = 1024                             // default line block
	DefCutter        = " /\r\n\\[](){}:=\"',"           // default cutter for finding KV object in string
	DefMaxItem       = 1024 * 4                         // getMax input items for MAP API
	DefMaxCallDeep   = 5                                // getMax call depth for MaskStruct
)

var (
	DefMaxLogInput    int32 = 1024 // default 1KB, the getMax input length for log, change it in conf
	DefMaxRegexRuleID int32 = 0    // default 0, no regex rule will be used for log default, change it in conf
)

// Engine Object implements all DLP API functions
type Engine struct {
	Version      string
	callerID     string
	endPoint     string
	accessKey    string
	secretKey    string
	isLegal      bool // true: auth is ok, false: auth failed
	isClosed     bool // true: Close() has been called
	isForLog     bool // true: NewLogProcessor() has been called, will not do other API
	isConfigured bool // true: ApplyConfig* API has been called, false: not been called
	confObj      *conf.DlpConf
	detectorMap  map[int32]detector.API
	maskerMap    map[string]mask.API
}

// NewEngine creates an Engine Object
//
//	Parameters:
//		callerID: caller ID at the dlp management system.
//
//	Return:
//		EngineAPI Object
//
//	Comment: 不要放在循环中调用
func NewEngine(callerID string) (header.EngineAPI, error) {
	defer recoveryImplStatic()
	eng := new(Engine)
	eng.Version = Version
	eng.callerID = callerID
	eng.detectorMap = make(map[int32]detector.API)
	eng.maskerMap = make(map[string]mask.API)
	return eng, nil
}

// Close release inner object, such as detector and masker
func (I *Engine) Close() {
	defer I.recoveryImpl()
	for k, v := range I.detectorMap {
		if v != nil {
			v.Close()
			I.detectorMap[k] = nil
		}
	}
	for k, v := range I.maskerMap {
		if v != nil {
			I.maskerMap[k] = nil
		}
	}
	I.detectorMap = nil
	I.confObj = nil
	I.isClosed = true
}

// ShowResults print results in console
// 打印识别结果
func (I *Engine) ShowResults(results []*header.DetectResult) {
	defer I.recoveryImpl()
	logger.Debugf("\n")
	logger.Debugf("\tTotal Results: %d\n", len(results))
	content, _ := json.Marshal(results)
	logger.Debugf("%s\n", string(content))
}

// GetVersion return DLP SDK version
func (I *Engine) GetVersion() string {
	defer I.recoveryImpl()
	return Version
}

// NewLogProcessor create a log processor for the package logs
// 调用过之后，eng只能用于log处理，因为规则会做专门的优化，不适合其他API使用
func (I *Engine) NewLogProcessor() header.Processor {
	defer I.recoveryImpl()

	I.isForLog = true
	_ = I.selectRulesForLog()
	return func(rawLog string, kvs ...interface{}) (string, []interface{}, bool) {
		// do not call log API in this func
		defer I.recoveryImpl()
		// do not call report at here, because this func will call DeIdentify()
		// Do not use logs function inside this function
		newLog := rawLog
		logCut := false
		if int32(len(newLog)) >= DefMaxLogInput {
			// cut for long log
			newLog = newLog[:DefMaxLogInput]
			logCut = true
		}
		newLog, _, _ = I.deIdentifyImpl(newLog)
		if logCut {
			newLog += DefLimitError
		}
		// logger.Debugf("LogProcessor rawLog: %s, kvs: %+v\n", rawLog, kvs)
		sz := len(kvs)
		// k1,v1,k2,v2,...
		if sz%2 != 0 {
			sz--
		}
		kvCut := false
		if sz >= DefMaxLogItem {
			// cut for too many items
			sz = DefMaxLogItem
			kvCut = true
		}
		retKvs := make([]interface{}, 0, sz)
		if sz > 0 {
			inMap := make(map[string]string)
			for i := 0; i < sz; i += 2 {
				keyStr := I.interfaceToStr(kvs[i])
				valStr := I.interfaceToStr(kvs[i+1])
				inMap[keyStr] = valStr
			}
			outMap, _, _ := I.deIdentifyMapImpl(inMap)
			for k, v := range outMap {
				v, _, _ = I.deIdentifyImpl(v)
				retKvs = append(retKvs, k, v)
			}
		}
		if kvCut {
			retKvs = append(retKvs, "<--[DLP Error]-->", DefLimitError)
		}
		return newLog, retKvs, true
	}
}

// NewEmptyLogProcessor will new a log processor which will do nothing
// 业务禁止使用
func (I *Engine) NewEmptyLogProcessor() header.Processor {
	return func(rawLog string, kvs ...interface{}) (string, []interface{}, bool) {
		return rawLog, kvs, true
	}
}

// ShowDlpConf print conf on console
func (I *Engine) ShowDlpConf() error {
	// copy obj
	confObj := *I.confObj
	out, err := yaml.Marshal(confObj)
	if err == nil {
		logger.Debugf("====godlp conf start====\n")
		logger.Debugf("%s\n", string(out))
		logger.Debugf("====godlp conf end====\n")
		return nil
	} else {
		return err
	}
}

// GetDefaultConf will return default config string
// 返回默认的conf string
func (I *Engine) GetDefaultConf() string {
	return DefConf
}

// DisableAllRules will disable all rules of engine
func (I *Engine) DisableAllRules() error {
	for i := range I.detectorMap {
		I.detectorMap[i] = nil
	}
	return nil
}

// private func
// interfaceToStr converts interface to string
func (I *Engine) interfaceToStr(in interface{}) string {
	out := ""
	switch in.(type) {
	case []byte:
		out = string(in.([]byte))
	case string:
		out = in.(string)
	default:
		out = fmt.Sprint(in)
	}
	return out
}

// loadDefCfg from the embedded resources
func (I *Engine) loadDefCfg() error {
	if confObj, err := conf.NewDlpConf(DefConf); err == nil {
		return I.applyConfigImpl(confObj)
	} else {
		return err
	}
}

// formatEndPoint formats endpoint
func (I *Engine) formatEndPoint(endpoint string) string {
	out := endpoint
	if !strings.HasPrefix(endpoint, "http") { // not( http or https)
		out = "http://" + endpoint // default use http
		out = strings.TrimSuffix(out, "/")
	}
	return out
}

func B2S(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func S2B(s string) (b []byte) {
	/* #nosec G103 */
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	/* #nosec G103 */
	sh := *(*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return b
}
