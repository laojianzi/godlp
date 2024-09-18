// Package dlp sdk detect.go implements DLP detect APIs
package dlp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/laojianzi/godlp/detector"
	"github.com/laojianzi/godlp/header"
	"github.com/laojianzi/godlp/internal/json"
)

// public func

// Detect find sensitive information for input string
// 对string进行敏感信息识别
func (I *Engine) Detect(inputText string) (retResults []*header.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return nil, header.ErrProcessAfterClose
	}
	if len(inputText) > DefMaxInput {
		return nil, fmt.Errorf("DefMaxInput: %d , %w", DefMaxInput, header.ErrMaxInputLimit)
	}
	retResults, retErr = I.detectImpl(inputText)
	return
}

// DetectMap detects KV map
// 对map[string]string进行敏感信息识别
func (I *Engine) DetectMap(inputMap map[string]string) (retResults []*header.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return nil, header.ErrProcessAfterClose
	}
	if len(inputMap) > DefMaxItem {
		return nil, fmt.Errorf("DefMaxItem: %d , %w", DefMaxItem, header.ErrMaxInputLimit)
	}
	inMap := make(map[string]string)
	for k, v := range inputMap {
		loK := strings.ToLower(k)
		inMap[loK] = v
	}
	retResults, retErr = I.detectMapImpl(inMap)
	return
}

// DetectJSON detects json string
// 对json string 进行敏感信息识别
func (I *Engine) DetectJSON(jsonText string) (retResults []*header.DetectResult, retErr error) {
	defer I.recoveryImpl()

	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return nil, header.ErrProcessAfterClose
	}
	retResults, _, retErr = I.detectJSONImpl(jsonText)
	return
}

// private func

// detectImpl works for the Detect API
func (I *Engine) detectImpl(inputText string) ([]*header.DetectResult, error) {
	rd := bufio.NewReaderSize(strings.NewReader(inputText), DefLineBlockSize)
	currPos := 0
	results := make([]*header.DetectResult, 0, DefResultSize)

	for {
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 {
			newLine := I.detectPre(line)
			lineResults := I.detectProcess(newLine)
			postResults := I.detectPost(lineResults, currPos)
			results = append(results, postResults...)
			currPos += len(newLine)
		}
		if err != nil {
			if err == io.EOF {
				break
			}

			// show err
		}
	}
	return results, nil
}

// detectPre calls prepare func before detect
func (I *Engine) detectPre(line []byte) []byte {
	line = I.unquoteEscapeChar(line)
	line = I.replaceWideChar(line)
	return line
}

// detectProcess detects sensitive info for a line
func (I *Engine) detectProcess(line []byte) []*header.DetectResult {
	// detect from a byte array
	bytesResults, _ := I.detectBytes(line)
	// detect from a kvList which is extracted from the byte array
	// kvList is used for the two item with same key
	kvList := I.extractKVList(line)
	kvResults, _ := I.detectKVList(kvList)
	results := I.mergeResults(bytesResults, kvResults)
	return results
}

// detectBytes detects for a line
func (I *Engine) detectBytes(line []byte) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0, DefResultSize)
	var retErr error
	// start := time.Now()
	for _, obj := range I.detectorMap {
		if obj != nil && obj.IsValue() {
			if I.isOnlyForLog() { // used in log processor mod, need very efficient
				if obj.GetRuleID() > DefMaxRegexRuleID && obj.UseRegex() { // if ID>MAX and rule uses regex
					continue // will not use this rule in log processor mod
				}
			}
			res, err := obj.DetectBytes(line)
			if err != nil {
				retErr = err
			}

			results = append(results, res...)
		}
	}
	// logger.Debugf("check rule:%d, len:%d, cast:%v\n", len(I.detectorMap), len(line), time.Since(start))

	// the last error will be returned
	return results, retErr
}

// extractKVList extracts KV item into a returned list
func (I *Engine) extractKVList(line []byte) []*detector.KVItem {
	kvList := make([]*detector.KVItem, 0, DefResultSize)

	sz := len(line)
	for i := 0; i < sz; {
		// k:v k=v k:=v k==v, chinese big "："
		ch, width := utf8.DecodeRune(line[i:])
		if width == 0 { // error
			break
		}

		if i+1 < sz && isEqualChar(ch) { // nolint: nestif
			left, right := "", ""
			vPos, kPos := []int{-1, -1}, []int{-1, -1}
			isFound := false
			if i+2 < sz {
				nx, nxWidth := utf8.DecodeRune(line[i+width:])
				if nx == '=' {
					left, kPos = lastToken(line, i)
					right, vPos = firstToken(line, i+width+nxWidth)
					isFound = true
				}
			}

			if !isFound {
				left, kPos = lastToken(line, i)
				right, vPos = firstToken(line, i+width)
				isFound = true
			}

			// logger.Debugf("%s [%d,%d) = %s [%d,%d)", left, kPos[0], kPos[1], right, vPos[0], vPos[1])
			_ = kPos

			if len(left) != 0 && len(right) != 0 {
				loLeft := strings.ToLower(left)
				kvList = append(kvList, &detector.KVItem{
					Key:   loLeft,
					Value: right,
					Start: vPos[0],
					End:   vPos[1],
				})
			}
		}

		i += width
	}
	return kvList
}

// isEqualChar checks whether the r is = or : or :=
func isEqualChar(r rune) bool {
	return r == ':' || r == '=' || r == '：'
}

// firstToken extract the first token from bytes, returns token and position info
func firstToken(line []byte, offset int) (string, []int) {
	sz := len(line)
	if offset >= 0 && offset < sz {
		st := offset
		ed := sz
		// find first non cutter
		for i := offset; i < sz; i++ {
			if strings.IndexByte(DefCutter, line[i]) == -1 {
				st = i
				break
			}
		}
		// find first cutter
		for i := st + 1; i < sz; i++ {
			if strings.IndexByte(DefCutter, line[i]) != -1 {
				ed = i
				break
			}
		}
		return string(line[st:ed]), []int{st, ed}
	} else { // out of bound
		return "", nil
	}
}

// lastToken extract the last token from bytes, returns token and position info
func lastToken(line []byte, offset int) (string, []int) {
	sz := len(line)
	if offset >= 0 && offset < sz {
		st := 0
		ed := offset
		// find first non cutter
		for i := offset - 1; i >= 0; i-- {
			if strings.IndexByte(DefCutter, line[i]) == -1 {
				ed = i + 1
				break
			}
		}
		// find first cutter
		for i := ed - 1; i >= 0; i-- {
			if strings.IndexByte(DefCutter, line[i]) != -1 {
				st = i + 1
				break
			}
		}
		return string(line[st:ed]), []int{st, ed}
	} else {
		return "", nil
	}
}

// detectKVList accepts kvList to do detection
func (I *Engine) detectKVList(kvList []*detector.KVItem) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0, DefResultSize)

	for _, obj := range I.detectorMap {
		if obj != nil && obj.IsKV() {
			if I.isOnlyForLog() { // used in log processor mod, need very efficient
				if obj.GetRuleID() > DefMaxRegexRuleID && obj.UseRegex() { // if ID>MAX and rule uses regex
					continue // will not use this rule in log processor mod
				}
			}
			// can not call I.DetectMap, because it will call mask, but position info has not been provided
			mapResults, _ := obj.DetectList(kvList)
			for i := range mapResults {
				// detectKVList is called from detect(), so result type will be VALUE
				mapResults[i].ResultType = detector.ResultTypeValue
			}

			results = append(results, mapResults...)
		}
	}
	return results, nil
}

// detectPost calls post func after detect
func (I *Engine) detectPost(results []*header.DetectResult, currPos int) []*header.DetectResult {
	ret := I.aJustResultPos(results, currPos)
	ret = I.maskResults(ret)
	return ret
}

// ResultList Result type define is used for sort in mergeResults
type ResultList []*header.DetectResult

// Len function is used for sort in mergeResults
func (a ResultList) Len() int {
	return len(a)
}

// Swap function is used for sort in mergeResults
func (a ResultList) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// Less function is used for sort in mergeResults
func (a ResultList) Less(i, j int) bool {
	if a[i].ByteStart < a[j].ByteStart {
		return true
	}

	if a[i].ByteStart == a[j].ByteStart {
		if a[i].ByteEnd < a[j].ByteEnd {
			return true
		}

		if a[i].ByteEnd == a[j].ByteEnd { // same
			return a[i].RuleID < a[j].RuleID
		}
	}

	return false
}

// Contain checks whether a[i] contains a[j]
func (a ResultList) Contain(i, j int) bool {
	return a[i].Key == a[j].Key && a[i].ByteStart <= a[j].ByteStart && a[j].ByteEnd <= a[i].ByteEnd
}

// Equal checks whether positions are equal
func (a ResultList) Equal(i, j int) bool {
	return a[i].ByteStart == a[j].ByteStart && a[j].ByteEnd == a[i].ByteEnd && a[i].Key == a[j].Key
}

// merge and sort two detect results
func (I *Engine) mergeResults(a []*header.DetectResult, b []*header.DetectResult) []*header.DetectResult {
	var total []*header.DetectResult
	if len(a) == 0 {
		total = b
	} else {
		if len(b) == 0 {
			total = a
		} else { // len(a)!=0 && len(b)!=0
			total = make([]*header.DetectResult, 0, len(a)+len(b))
			total = append(total, a...)
			total = append(total, b...)
		}
	}
	if len(total) == 0 { // nothing
		return total
	}
	// sort
	sort.Sort(ResultList(total))
	sz := len(total)
	mark := make([]bool, sz)
	// firstly, all elements will be left
	for i := 0; i < sz; i++ {
		mark[i] = true
	}

	for i := 0; i < sz; i++ {
		if !mark[i] {
			continue
		}

		for j := i + 1; j < sz; j++ {
			if !mark[j] {
				continue
			}

			// inner element will be ignored
			if ResultList(total).Equal(i, j) {
				mark[i] = false
				break
			}

			if ResultList(total).Contain(i, j) {
				mark[j] = false
			}

			if ResultList(total).Contain(j, i) {
				mark[i] = false
			}
		}
	}
	ret := make([]*header.DetectResult, 0, sz)
	for i := 0; i < sz; i++ {
		if mark[i] {
			ret = append(ret, total[i])
		}
	}
	return ret
}

// aJustResultPos a just position offset
func (I *Engine) aJustResultPos(results []*header.DetectResult, currPos int) []*header.DetectResult {
	if currPos > 0 {
		for i := range results {
			results[i].ByteStart += currPos
			results[i].ByteEnd += currPos
		}
	}
	return results
}

// maskResults fill result.MaskText by calling mask.MaskResult()
func (I *Engine) maskResults(results []*header.DetectResult) []*header.DetectResult {
	for _, res := range results {
		if d, ok := I.detectorMap[res.RuleID]; ok {
			maskRuleName := d.GetMaskRuleName()
			if maskWorker, ok := I.maskerMap[maskRuleName]; ok {
				_ = maskWorker.MaskResult(res)
			} else { // Not Found
				// logger.Errorf(fmt.Errorf("MaskRuleName: %s, Error: %w", maskRuleName, header.ErrMaskRuleNotfound).Error())
				res.MaskText = res.Text
			}
		}
	}
	return results
}

// detectMapImpl detect sensitive info for inputMap
func (I *Engine) detectMapImpl(inputMap map[string]string) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0, DefResultSize)
	for _, obj := range I.detectorMap {
		if obj != nil {
			res, err := obj.DetectMap(inputMap)
			if err == nil {
				results = append(results, res...)
			}

			// logger.Errorf(err.Error())
		}
	}
	// merge result to reduce combined item
	results = I.mergeResults(results, nil)
	results = I.maskResults(results)

	return results, nil
}

func getMin(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func getMax(x, y int) int {
	if x < y {
		return y
	}
	return x
}

// detectJSONImpl implements detectJSON
func (I *Engine) detectJSONImpl(jsonText string) (results []*header.DetectResult, kvMap map[string]string, err error) {
	var jsonObj interface{}
	err = json.Unmarshal([]byte(jsonText), &jsonObj)
	if err != nil {
		var e *json.SyntaxError
		if errors.As(err, &e) {
			return nil, nil, fmt.Errorf("%s: offset[%d], str[%s]", err.Error(), e.Offset,
				jsonText[getMax(int(e.Offset)-4, 0):getMin(int(e.Offset+10), len(jsonText))])
		}
		return nil, nil, err
	}

	// logger.Debugf("%+v\n", jsonObj)
	kvMap = make(map[string]string)
	I.dfsJSON("", &jsonObj, kvMap, false)
	results, err = I.detectMapImpl(kvMap)
	for _, item := range results {
		if orig, ok := kvMap[item.Key]; ok {
			if out, err := I.deIdentifyByResult(orig, []*header.DetectResult{item}); err == nil {
				kvMap[item.Key] = out
			}
		}
	}
	return
}

var wideCharMap = map[rune]string{
	'【': "  [",
	'】': "]  ",
	'：': "  :", // must use [space,space,:], for :=
	'「': "  {",
	'」': "}  ",
	'（': "  (",
	'）': ")  ",
	'《': "  <",
	'》': ">  ",
	'。': ".  ",
	'？': "?  ",
	'！': "!  ",
	'，': ",  ",
	'、': ",  ",
	'；': ";  ",
}

// replaceWideChar replace wide char with one byte char
func (I *Engine) replaceWideChar(lineArray []byte) []byte {
	sz := len(lineArray)
	for i := 0; i < sz; {
		if (lineArray[i] & 0x80) != 0x80 { // ascii char
			i++
			continue
		}

		r, width := utf8.DecodeRune(lineArray[i:])
		if width == 0 { // error
			break
		}

		if s, ok := wideCharMap[r]; ok {
			copy(lineArray[i:i+width], s)
		}

		i += width
	}

	return lineArray
}

// unquoteEscapeChar replace escaped char with original char
func (I *Engine) unquoteEscapeChar(lineArray []byte) []byte {
	sz := len(lineArray)
	for i := 0; i < sz; {
		r := lineArray[i]
		if r == '\\' {
			// last 2 char
			if i+1 < sz {
				value := byte(' ')

				c := lineArray[i+1]
				switch c {
				case 'a':
					value = '\a'
				case 'b':
					value = '\b'
				case 'f':
					value = '\f'
				case 'n':
					value = '\n'
				case 'r':
					value = '\r'
				case 't':
					value = '\t'
				case 'v':
					value = '\v'
				case '\\':
					value = '\\'
				case '"':
					value = '"'
				case '\'':
					value = '\''
				}
				lineArray[i] = byte(' ') // space ch
				lineArray[i+1] = value
				i += 2
			} else {
				i++
			}
		} else {
			i++
		}
	}
	return lineArray
}
