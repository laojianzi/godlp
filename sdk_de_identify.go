// Package dlp sdk deIdentify.go implements deIdentify related APIs
package dlp

import (
	"encoding/json"
	"fmt"

	"github.com/bytedance/godlp/header"
)

// DeIdentify detects string firstly, then return masked string and results
// 对string先识别，然后按规则进行打码
// public func
func (I *Engine) DeIdentify(inputText string) (outputText string, retResults []*header.DetectResult, retErr error) {
	defer I.recoveryImpl()
	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return "", nil, header.ErrProcessAfterClose
	}
	if I.isOnlyForLog() {
		return inputText, nil, header.ErrOnlyForLog
	}
	if len(inputText) > DefMaxInput {
		return inputText, nil, fmt.Errorf("DefMaxInput: %d , %w", DefMaxInput, header.ErrMaxInputLimit)
	}
	outputText, retResults, retErr = I.deIdentifyImpl(inputText)
	return
}

// DeIdentifyMap detects KV map firstly,then return masked map
// 对map[string]string先识别，然后按规则进行打码
func (I *Engine) DeIdentifyMap(inputMap map[string]string) (outMap map[string]string, retResults []*header.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return nil, nil, header.ErrProcessAfterClose
	}
	if len(inputMap) > DefMaxItem {
		return inputMap, nil, fmt.Errorf("DefMaxItem: %d , %w", DefMaxItem, header.ErrMaxInputLimit)
	}
	outMap, retResults, retErr = I.deIdentifyMapImpl(inputMap)
	return
}

// DeIdentifyJSON detects JSON firstly, then return masked json object in string format and results
// 对jsonText先识别，然后按规则进行打码，返回打码后的JSON string
func (I *Engine) DeIdentifyJSON(jsonText string) (outStr string, retResults []*header.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return jsonText, nil, header.ErrProcessAfterClose
	}
	outStr = jsonText
	if results, kvMap, err := I.detectJSONImpl(jsonText); err == nil {
		retResults = results
		var jsonObj interface{}
		if err := json.Unmarshal([]byte(jsonText), &jsonObj); err == nil {
			// kvMap := I.resultsToMap(results)
			outObj := I.dfsJSON("", &jsonObj, kvMap, true)
			if outJSON, err := json.Marshal(outObj); err == nil {
				outStr = string(outJSON)
			} else {
				retErr = err
			}
		} else {
			retErr = err
		}
	} else {
		retErr = err
	}
	return
}

// DeIdentifyJSONByResult  returns masked json object in string format from the passed-in []*header.DetectResult.
// You may want to call DetectJSON first to obtain the []*header.DetectResult.
// 根据传入的 []*header.DetectResult 对 Json 进行打码，返回打码后的JSON string
func (I *Engine) DeIdentifyJSONByResult(jsonText string, detectResults []*header.DetectResult) (outStr string, retErr error) {
	defer I.recoveryImpl()
	// have to use closure to pass retResults parameters
	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return jsonText, header.ErrProcessAfterClose
	}
	outStr = jsonText
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(jsonText), &jsonObj); err == nil {
		kvMap := I.resultsToMap(detectResults)
		outObj := I.dfsJSON("", &jsonObj, kvMap, true)
		if outJSON, err := json.Marshal(outObj); err == nil {
			outStr = string(outJSON)
		} else {
			retErr = err
		}
	} else {
		retErr = err
	}

	return
}

// deIdentifyImpl implements DeIdentify string
// private func
func (I *Engine) deIdentifyImpl(inputText string) (outputText string, retResults []*header.DetectResult, retErr error) {
	outputText = inputText // default same text
	if arr, err := I.detectImpl(inputText); err == nil {
		retResults = arr
		if out, err := I.deIdentifyByResult(inputText, retResults); err == nil {
			outputText = out
		} else {
			retErr = err
		}
	} else {
		retErr = err
	}
	return
}

// deIdentifyMapImpl implements DeIdentifyMap
func (I *Engine) deIdentifyMapImpl(inputMap map[string]string) (outMap map[string]string, retResults []*header.DetectResult, retErr error) {
	outMap = make(map[string]string)
	if results, err := I.detectMapImpl(inputMap); err == nil {
		if len(results) == 0 { // detect nothing
			return inputMap, results, nil
		} else {
			outMap = inputMap
			for _, item := range results {
				if orig, ok := outMap[item.Key]; ok {
					if out, err := I.deIdentifyByResult(orig, []*header.DetectResult{item}); err == nil {
						outMap[item.Key] = out
					}
				}
			}
			retResults = results
		}
	} else {
		outMap = inputMap
		retErr = err
	}
	return
}

// deIdentifyByResult concatenate MaskText
func (I *Engine) deIdentifyByResult(in string, arr []*header.DetectResult) (string, error) {
	out := make([]byte, 0, len(in)+8)
	pos := 0
	inArr := S2B(in)
	for _, res := range arr {
		if pos < res.ByteStart {
			out = append(out, inArr[pos:res.ByteStart]...)
		}
		out = append(out, []byte(res.MaskText)...)
		pos = res.ByteEnd
	}
	if pos < len(in) {
		out = append(out, inArr[pos:]...)
	}
	outStr := B2S(out)
	return outStr, nil
}

// resultsToMap convert results array into Map[Key]=MaskText
func (I *Engine) resultsToMap(results []*header.DetectResult) map[string]string {
	kvMap := make(map[string]string)
	for _, item := range results {
		kvMap[item.Key] = item.MaskText
	}
	return kvMap
}
