// Package dlp sdk internal.go implements internal API for DLP
package dlp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/bytedance/godlp/detector"
	"github.com/bytedance/godlp/header"
	"github.com/bytedance/godlp/log"
	"github.com/bytedance/godlp/mask"
)

type HttpResponseBase struct {
	RetCode int    `json:"ret_code"`
	RetMsg  string `json:"ret_msg"`
}

type DescribeRulesResponse struct {
	HttpResponseBase
	Rule []byte `json:"rule,omitempty"`
	Crc  uint32 `json:"crc,omitempty"` // rule 的crc
}

// private func

// recoveryImplStatic implements recover if panic which is used for NewEngine API
func recoveryImplStatic() {
	if r := recover(); r != nil {
		if isCriticalPanic(r.(error)) {
			panic(r)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "%s, msg: %+v\n", header.ErrPanic.Error(), r)
			debug.PrintStack()
		}
	}
}

// recoveryImpl implements recover if panic
func (I *Engine) recoveryImpl() {
	if r := recover(); r != nil {
		if isCriticalPanic(r.(error)) {
			panic(r)
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "%s, msg: %+v\n", header.ErrPanic.Error(), r)
			debug.PrintStack()
		}
	}
}

// isCriticalPanic checks whether error is critical error
func isCriticalPanic(r error) bool {
	return errors.Is(r, header.ErrHasNotConfigured)
}

// hasClosed check whether the engine has been closed
func (I *Engine) hasClosed() bool {
	return I.isClosed
}

func (I *Engine) isOnlyForLog() bool {
	return I.isForLog
}

// hasConfigured check whether the engine has been configured
func (I *Engine) hasConfigured() bool {
	return I.isConfigured
}

// postLoadConfig will load config object
func (I *Engine) postLoadConfig() error {
	if I.confObj.Global.MaxLogInput > 0 {
		DefMaxLogInput = I.confObj.Global.MaxLogInput
	}
	if I.confObj.Global.MaxRegexRuleID > 0 {
		DefMaxRegexRuleID = I.confObj.Global.MaxRegexRuleID
	}
	if err := I.initLogger(); err != nil {
		return err
	}
	if err := I.loadDetector(); err != nil {
		return err
	}
	if err := I.loadMaskWorker(); err != nil {
		return err
	}
	I.isConfigured = true
	return nil
}

// isDebugMode checks if DLP is in debug mode
func (I *Engine) isDebugMode() bool {
	return strings.Compare(strings.ToLower(I.confObj.Global.Mode), "debug") == 0
}

// initLogger inits logger obj, in debug mode, log message will be printed in console and log file,
// in release mode, log level is ERROR and log message will be printed into stderr
func (I *Engine) initLogger() error {
	if I.isDebugMode() {
		// log.SetLevel(0)
		log.Debugf("DLP@%s run in debug mode", I.Version)
	} else { // release mode
		// log.SetLevel(log.LevelError)
	}
	return nil
}

// loadDetector loads detectors from config
func (I *Engine) loadDetector() error {
	// fill detectorMap
	if err := I.fillDetectorMap(); err != nil {
		return err
	}
	// disable rules
	return I.disableRulesImpl(I.confObj.Global.DisableRules)
}

// loadMaskWorker loads mask worker from config
func (I *Engine) loadMaskWorker() error {
	maskRuleList := I.confObj.MaskRules
	if I.maskerMap == nil {
		I.maskerMap = make(map[string]mask.API)
	}
	for _, rule := range maskRuleList {
		if obj, err := mask.NewWorker(rule, I); err == nil {
			ruleName := obj.GetRuleName()
			if old, ok := I.maskerMap[ruleName]; ok {
				log.Errorf("ruleName: %s, error: %s", old.GetRuleName(), header.ErrLoadMaskNameConflict.Error())
			} else {
				I.maskerMap[ruleName] = obj
			}
		}
	}
	return nil
}

// dfsJSON walk a json object, used for DetectJSON and DeIdentifyJSON
// in DetectJSON(), isDeIdentify is false, kvMap is written only, will store json object path and value
// in DeIdentifyJSON(), isDeIdentify is true, kvMap is read only, will store path and MaskText of sensitive information
func (I *Engine) dfsJSON(path string, ptr *interface{}, kvMap map[string]string, isDeIdentify bool) interface{} {
	path = strings.ToLower(path)
	switch (*ptr).(type) {
	case map[string]interface{}:
		for k, v := range (*ptr).(map[string]interface{}) {
			subPath := path + "/" + k
			(*ptr).(map[string]interface{})[k] = I.dfsJSON(subPath, &v, kvMap, isDeIdentify)
		}
	case []interface{}:
		for i, v := range (*ptr).([]interface{}) {
			subPath := ""
			if len(path) == 0 {
				subPath = fmt.Sprintf("/[%d]", i)
			} else {
				subPath = fmt.Sprintf("%s[%d]", path, i)
			}
			(*ptr).([]interface{})[i] = I.dfsJSON(subPath, &v, kvMap, isDeIdentify)
		}
	case string:
		var subObj interface{}
		if val, ok := (*ptr).(string); ok {
			// try nested json Unmarshal
			if I.maybeJSON(val) {
				if err := json.Unmarshal([]byte(val), &subObj); err == nil {
					obj := I.dfsJSON(path, &subObj, kvMap, isDeIdentify)
					if ret, err := json.Marshal(obj); err == nil {
						retStr := string(ret)
						return retStr
					} else {
						return obj
					}
				}
			} else { // plain text
				if isDeIdentify {
					if kvMask, ok := kvMap[path]; ok {
						return kvMask
					} else {
						return val
					}
				} else {
					kvMap[path] = val
					return val
				}
			}
		}
	}
	return *ptr
}

// maybeJSON check whether input string is a JSON object or array
func (I *Engine) maybeJSON(in string) bool {
	maybeObj := strings.IndexByte(in, '{') != -1 && strings.LastIndexByte(in, '}') != -1
	maybeArray := strings.IndexByte(in, '[') != -1 && strings.LastIndexByte(in, ']') != -1
	return maybeObj || maybeArray
}

// selectRulesForLog will select rules for log
func (I *Engine) selectRulesForLog() error {
	return nil
}

func (I *Engine) fillDetectorMap() error {
	ruleList := I.confObj.Rules
	if I.detectorMap == nil {
		I.detectorMap = make(map[int32]detector.API)
	}
	enableRules := I.confObj.Global.EnableRules
	fullSet := map[int32]bool{}
	for _, rule := range ruleList {
		if obj, err := detector.NewDetector(rule); err == nil {
			ruleID := obj.GetRuleID()
			I.detectorMap[ruleID] = obj
			fullSet[ruleID] = false
		} else {
			log.Errorf(err.Error())
		}
	}
	// if EnableRules is empty, all rules are loaded
	// else only some rules are enabled.
	if len(enableRules) > 0 {
		for _, ruleID := range enableRules {
			if _, ok := I.detectorMap[ruleID]; ok {
				fullSet[ruleID] = true
			}
		}
		for k, v := range fullSet {
			if !v {
				I.detectorMap[k] = nil
			}
		}
	}
	return nil
}

// disableRules will disable rules based on ruleList, pass them all
// 禁用规则，原子操作，每次禁用是独立操作，不会有历史依赖
func (I *Engine) applyDisableRules(ruleList []int32) {
	I.confObj.Global.DisableRules = ruleList
	_ = I.loadDetector()
}

func (I *Engine) disableRulesImpl(ruleList []int32) error {
	for _, ruleID := range ruleList {
		if _, ok := I.detectorMap[ruleID]; ok {
			I.detectorMap[ruleID] = nil
		}
	}
	total := 0
	for k, rule := range I.detectorMap {
		if rule != nil {
			total++
		} else {
			delete(I.detectorMap, k)
		}
	}
	if I.isDebugMode() {
		log.Debugf("Total %d Rule loaded", total)
	}
	return nil
}
