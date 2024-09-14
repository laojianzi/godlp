// Package detector implements detector functions
package detector

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/bytedance/godlp/conf"

	"github.com/bytedance/godlp/header"
)

// RuleType is different with ResultType, because for input string contains KV object, KV rule will generate Value Detect Type
const (
	RuleTypeValue        = 0
	RuleTypeKv           = 1
	ResultTypeValue      = "VALUE"
	ResultTypeKv         = "KV"
	BlacklistAlgoMasked  = "MASKED"
	VerifyAlgoIDCard     = "IDCARD"
	VerifyAlgoAbaRouting = "ABAROUTING"
	VerifyAlgoCreditCard = "CREDITCARD"
	VerifyAlgoBitcoin    = "BITCOIN"
	VerifyAlgoDomain     = "DOMAIN"
	MaskedCharList       = "*#"
	DefResultSize        = 4
	DefContextRange      = 32
	DefIDCardLength      = 18
)

// ContextVerifyFunc defines verify by context function
type ContextVerifyFunc func(*Detector, []byte, *header.DetectResult) bool

type Detector struct {
	rule     conf.RuleItem // rule item in conf
	RuleType int           // VALUE if there is no KReg and KDict
	// Detect section in conf
	KReg  []*regexp.Regexp    // regex list for Key
	KDict map[string]struct{} // Dict for Key
	VReg  []*regexp.Regexp    // Regex list for Value
	VDict []string            // Dict for Value
	// Filter section in conf
	BAlgo []string         // algorithm for blacklist, supports MASKED
	BDict []string         // Dict for blacklist
	BReg  []*regexp.Regexp // Regex list for blacklist
	// Verify section in conf
	CDict []string         // Dict for Context Verification
	CReg  []*regexp.Regexp // Regex List for Context Verification
	VAlgo []string         // algorithm for verify action, such as IDCARD
}

type KVItem struct {
	Key   string
	Value string
	Start int
	End   int
}

type API interface {
	// GetRuleInfo returns rule as string
	GetRuleInfo() string
	// GetRuleID returns RuleID
	GetRuleID() int32
	// GetMaskRuleName returns MaskRuleName
	GetMaskRuleName() string
	// IsValue checks whether RuleType is VALUE
	IsValue() bool
	// IsKV IsValue checks whether RuleType is KV
	IsKV() bool
	// UseRegex checks whether Rule use Regex
	UseRegex() bool
	// DetectBytes detects sensitive info for bytes
	DetectBytes(inputBytes []byte) ([]*header.DetectResult, error)
	// DetectMap detects sensitive info for map
	DetectMap(inputMap map[string]string) ([]*header.DetectResult, error)
	// DetectList detects sensitive info for list
	DetectList(kvList []*KVItem) ([]*header.DetectResult, error)
	// Close release detector object
	Close()
}

// NewDetector creates detector object from rule
func NewDetector(ruleItem conf.RuleItem) (API, error) {
	obj := new(Detector)
	obj.rule = ruleItem
	obj.prepare()
	return obj, nil
}

// GetRuleInfo returns rule as string
// public func
func (I *Detector) GetRuleInfo() string {
	return fmt.Sprintf("%+v", I.rule)
}

// GetRuleID returns RuleID
func (I *Detector) GetRuleID() int32 {
	return I.rule.RuleID
}

// GetMaskRuleName returns MaskRuleName used in Detect Rule
func (I *Detector) GetMaskRuleName() string {
	return I.rule.Mask
}

// IsValue checks whether Detect RuleType is VALUE
func (I *Detector) IsValue() bool {
	return I.RuleType == RuleTypeValue
}

// IsKV checks whether Detect RuleType is KV
func (I *Detector) IsKV() bool {
	return I.RuleType == RuleTypeKv
}

// UseRegex checks whether Rule use Regex
func (I *Detector) UseRegex() bool {
	return len(I.KReg) > 0 || len(I.VReg) > 0
}

// DetectBytes detects sensitive info for bytes, is called from Detect()
func (I *Detector) DetectBytes(inputBytes []byte) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0, DefResultSize)
	for _, reObj := range I.VReg {
		if ret, err := I.regexDetectBytes(reObj, inputBytes); err == nil {
			results = append(results, ret...)
		} else {
			// logger.Errorf(err.Error())
		}
	}
	for _, item := range I.VDict {
		if ret, err := I.dictDetectBytes([]byte(item), inputBytes); err == nil {
			results = append(results, ret...)
		} else {
			// logger.Errorf(err.Error())
		}
	}
	results = I.filter(results)
	results = I.verify(inputBytes, results)
	return results, nil
}

// DetectMap detects for Map, is called from DetectMap() and DetectJSON()
func (I *Detector) DetectMap(inputMap map[string]string) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0)

	// (KReg || KDict) && (VReg || VDict)
	item := &KVItem{
		Start: 0,
		End:   0,
	}
	for inK, inV := range inputMap {
		item.Key = inK
		item.Value = inV
		I.doDetectKV(item, &results)
	}
	return results, nil
}

// DetectList detects for List
func (I *Detector) DetectList(kvList []*KVItem) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0)

	length := len(kvList)
	for i := 0; i < length; i++ {
		I.doDetectKV(kvList[i], &results)
	}
	return results, nil
}

func (I *Detector) doDetectKV(kvItem *KVItem, results *[]*header.DetectResult) {
	// inK may be a path of json object
	lastKey, ifExtracted := I.getLastKey(kvItem.Key)
	if I.IsKV() {
		// key rules check
		// Dict rules first, then regex rule
		_, hit := I.KDict[lastKey]
		if (!hit) && ifExtracted {
			_, hit = I.KDict[kvItem.Key]
		}

		if !hit {
			for _, re := range I.KReg {
				if re.Match([]byte(lastKey)) {
					hit = true
					break
				}
			}
		}
		if hit { // key rule is hit
			if len(I.VDict) == 0 && len(I.VReg) == 0 { // no value rule
				if res, err := I.createKVResult(kvItem.Key, kvItem.Value); err == nil {
					res.ByteStart += kvItem.Start
					res.ByteEnd += kvItem.Start
					*results = append(*results, res)
				}
			} else { // check value rule
				if vResults, err := I.DetectBytes([]byte(kvItem.Value)); err == nil {
					for _, res := range vResults {
						// convert VALUE result into KV result
						res.ResultType = ResultTypeKv
						res.Key = kvItem.Key
						res.ByteStart += kvItem.Start
						res.ByteEnd += kvItem.Start
						*results = append(*results, res)
					}
				}
			}
		}
	} else { // only value rule
		if vResults, err := I.DetectBytes([]byte(kvItem.Value)); err == nil {
			for _, res := range vResults {
				// use VALUE because value rule
				res.ResultType = ResultTypeValue
				res.Key = kvItem.Key
				res.ByteStart += kvItem.Start
				res.ByteEnd += kvItem.Start
				*results = append(*results, res)
			}
		}
	}
}

// Close release detector object
func (I *Detector) Close() {
	for i := range I.VReg {
		I.VReg[i] = nil
	}
	// Detect section
	I.KDict = nil
	I.releaseReg(I.KReg)
	I.KReg = nil
	I.VDict = nil
	I.releaseReg(I.VReg)
	I.VReg = nil

	// Filter section
	I.BAlgo = nil
	I.BDict = nil
	I.releaseReg(I.BReg)
	I.BReg = nil

	// Verify section
	I.CDict = nil
	I.releaseReg(I.CReg)
	I.CReg = nil
	I.VAlgo = nil
}

// private func

// prepare will prepare detector object from rule
func (I *Detector) prepare() {
	// Detect
	I.KReg = I.preCompile(I.rule.Detect.KReg)
	I.KDict = lowerStringList2Map(I.rule.Detect.KDict)
	I.VReg = I.preCompile(I.rule.Detect.VReg)
	I.VDict = I.rule.Detect.VDict

	// Filter
	I.BReg = I.preCompile(I.rule.Filter.BReg)
	I.BAlgo = I.rule.Filter.BAlgo
	I.BDict = I.rule.Filter.BDict
	// Verify
	I.CReg = I.preCompile(I.rule.Verify.CReg)
	I.CDict = I.rule.Verify.CDict
	I.VAlgo = I.rule.Verify.VAlgo
	I.setRuleType()
}

// setRuleType set RuleType based on K V in detect section of config
func (I *Detector) setRuleType() {
	if len(I.KDict) == 0 && len(I.KReg) == 0 { // no key rules means RuleType is VALUE
		I.RuleType = RuleTypeValue
	} else { // RuleType is KV
		I.RuleType = RuleTypeKv
	}
}

// releaseReg will set item of list as nil
func (I *Detector) releaseReg(list []*regexp.Regexp) {
	for i := range list {
		list[i] = nil
	}
}

// preCompile compiles regex string list then return regex list
func (I *Detector) preCompile(reList []string) []*regexp.Regexp {
	list := make([]*regexp.Regexp, 0, DefResultSize)
	for _, reStr := range reList {
		if re, err := regexp.Compile(reStr); err == nil {
			list = append(list, re)
		} else {
			// logger.Errorf("Regex %s ,error: %w", reStr, err)
		}
	}
	return list
}

// preToLower modify dictList to lower case
func (I *Detector) preToLower(dictList []string) []string {
	for i, item := range dictList {
		dictList[i] = strings.ToLower(item)
	}
	return dictList
}

func lowerStringList2Map(dictList []string) map[string]struct{} {
	l := len(dictList)
	if l == 0 {
		return nil
	}
	m := make(map[string]struct{}, l+1)
	for i := 0; i < l; i++ {
		m[strings.ToLower(dictList[i])] = struct{}{}
	}
	return m
}

// regexDetectBytes use regex to detect input bytes
func (I *Detector) regexDetectBytes(re *regexp.Regexp, inputBytes []byte) ([]*header.DetectResult, error) {
	if re == nil {
		return nil, header.ErrReEmpty
	}
	results := make([]*header.DetectResult, 0, DefResultSize)
	if ret := re.FindAllIndex(inputBytes, -1); ret != nil {
		for i := range ret {
			pos := ret[i]
			if res, err := I.createValueResult(inputBytes, pos); err == nil {
				results = append(results, res)
			}
		}
	}
	return results, nil
}

// dictDetectBytes finds whether word in input bytes
func (I *Detector) dictDetectBytes(word []byte, inputBytes []byte) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0, DefResultSize)
	current := inputBytes
	currStart := 0
	for len(current) > 0 {
		start := bytes.Index(current, word)
		if start == -1 { // not found
			break
		} else { // found, then move forward
			currStart += start
			end := currStart + len(word)
			pos := []int{currStart, end}
			if res, err := I.createValueResult(inputBytes, pos); err == nil {
				results = append(results, res)
			}
			current = inputBytes[end:]
			currStart = end
		}
	}
	return results, nil
}

// createValueResult creates value result item
func (I *Detector) createValueResult(inputBytes []byte, pos []int) (ret *header.DetectResult, err error) {
	if len(pos) != 2 {
		return nil, header.ErrPositionError
	}
	ret = I.newResult()
	ret.Text = string(inputBytes[pos[0]:pos[1]])
	ret.ResultType = ResultTypeValue
	ret.ByteStart = pos[0]
	ret.ByteEnd = pos[1]
	return ret, nil
}

// createKVResult creates kv result
func (I *Detector) createKVResult(inK string, inV string) (*header.DetectResult, error) {
	ret := I.newResult()
	ret.Text = inV
	ret.ResultType = ResultTypeKv
	ret.ByteStart = 0
	ret.ByteEnd = len(inV)
	ret.Key = inK
	return ret, nil
}

// newResult new result
func (I *Detector) newResult() *header.DetectResult {
	ret := new(header.DetectResult)
	ret.RuleID = I.rule.RuleID
	ret.InfoType = I.rule.InfoType
	ret.EnName = I.rule.EnName
	ret.CnName = I.rule.CnName
	ret.ExtInfo = I.rule.ExtInfo
	ret.Level = I.rule.Level
	return ret
}

// filter will process filter condition
func (I *Detector) filter(in []*header.DetectResult) []*header.DetectResult {
	out := make([]*header.DetectResult, 0, DefResultSize)
	for i := range in {
		res := in[i]
		found := false
		for _, word := range I.BDict {
			// Found in BlackList BDict
			if strings.Compare(res.Text, word) == 0 {
				found = true
				break
			}
		}
		if found == false {
			for _, re := range I.BReg {
				// Found in BlackList BReg
				if re.Match([]byte(res.Text)) {
					found = true
					break
				}
			}
		}
		if found == false {
			for _, algo := range I.BAlgo {
				switch algo {
				case BlacklistAlgoMasked:
					if I.isMasked(res.Text) {
						found = true
						break
					}
				}
			}
		}
		if found == false {
			out = append(out, res)
		}
	}
	return out
}

// isMasked checks input whether contain * or #
func (I *Detector) isMasked(in string) bool {
	pos := strings.IndexAny(in, MaskedCharList)
	return pos != -1 // found mask char
}

// verify use verify config to check results
func (I *Detector) verify(inputBytes []byte, in []*header.DetectResult) []*header.DetectResult {
	out := make([]*header.DetectResult, 0, DefResultSize)
	markList := make([]bool, len(in))
	for i := range markList {
		markList[i] = true
	}
	if len(I.CDict) != 0 || len(I.CReg) != 0 { // need context check
		for i, res := range in {
			if !I.verifyByContext(inputBytes, res) { // check failed
				markList[i] = false
			}
		}
	}
	if len(I.VAlgo) != 0 { // need verify algorithm check
		for i, res := range in {
			if markList[i] == true {
				for _, algo := range I.VAlgo {
					switch algo {
					case VerifyAlgoIDCard:
						if !I.verifyByIDCard(res) { // check failed
							markList[i] = false
						}
					case VerifyAlgoAbaRouting:
						if !I.verifyByABARouting(res) {
							markList[i] = false
						}
					case VerifyAlgoCreditCard:
						if !I.verifyByCreditCard(res) {
							markList[i] = false
						}
					case VerifyAlgoBitcoin:
						if !I.verifyByBitCoin(res) {
							markList[i] = false
						}
					case VerifyAlgoDomain:
						if !I.verifyByDomain(res) {
							markList[i] = false
						}

					}
				}
			}
		}
	}
	for i, need := range markList {
		if need {
			out = append(out, in[i])
		}
	}
	return out
}

// verifyByContext check around context to decide whether res is accuracy
func (I *Detector) verifyByContext(inputBytes []byte, res *header.DetectResult) bool {
	st := res.ByteStart - DefContextRange
	if st < 0 {
		st = 0
	}
	ed := res.ByteEnd + DefContextRange
	lenInput := len(inputBytes)
	if ed > lenInput {
		ed = lenInput
	}
	subInput := inputBytes[st:ed]
	// to lower
	subInput = bytes.ToLower(subInput)
	for _, word := range I.CDict {
		if len(word) == 0 {
			continue
		}
		wordBytes := []byte(strings.ToLower(word))
		pos := bytes.Index(subInput, wordBytes)
		for start := 0; pos != -1; pos = bytes.Index(subInput[start:], wordBytes) {
			if I.isWholeWord(subInput[start:], wordBytes, pos) {
				return true
			}
			start += pos + len(word)
		}
	}

	var found bool
	for _, re := range I.CReg {
		if re.Match(subInput) {
			found = true
			break
		}
	}

	return found
}

// isWholeWord checks whether word which is found in input is a whole word
func (I *Detector) isWholeWord(in []byte, word []byte, pos int) bool {
	if pos == -1 {
		return false
	}

	leftPos := pos
	rightPos := pos + len(word)
	if leftPos < 0 {
		leftPos = 0
	}
	if rightPos >= len(in) { /* the maximum rightPos can be len(in)*/
		rightPos = len(in)
	}

	left, leftSz := utf8.DecodeLastRune(in[:leftPos])
	right, rightSz := utf8.DecodeRune(in[rightPos:])
	// be careful, unicode.IsLetter('中') == true
	if rightSz > 1 || leftSz > 1 { // left or right is Chinese char
		return true
		// bad case:
		// in: 汉字ABCDE汉字
		// word:  ABC
	}
	if leftSz == 0 {
		if rightSz == 0 {
			return true
		} else {
			return !I.isLetter(right)
		}
	} else {
		if rightSz == 0 {
			return !I.isLetter(left)
		} else {
			return !I.isLetter(left) && !I.isLetter(right)
		}
	}
}

// isLetter checks whether r is a-zA-z
func (I *Detector) isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// verifyByIDCard checks whether result is IDCard
func (I *Detector) verifyByIDCard(res *header.DetectResult) bool {
	idCard := res.Text
	sz := len(idCard)
	if sz != DefIDCardLength { // length check failed
		return false
	}
	weight := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	validate := []byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}
	sum := 0
	for i := 0; i < len(weight); i++ {
		sum += weight[i] * int(byte(idCard[i])-'0')
	}
	m := sum % 11
	return validate[m] == idCard[sz-1]
}

// for bitcoin verify
type a25 [25]byte

func (a *a25) version() byte {
	return a[0]
}

func (a *a25) embeddedChecksum() (c [4]byte) {
	copy(c[:], a[21:])
	return
}

// DoubleSHA256 computes a double sha256 hash of the first 21 bytes of the
// address.  This is the one function shared with the other bitcoin RC task.
// Returned is the full 32 byte sha256 hash.  (The bitcoin checksum will be
// the first four bytes of the slice.)
func (a *a25) doubleSHA256() []byte {
	h := sha256.New()
	h.Write(a[:21])
	d := h.Sum([]byte{})
	h = sha256.New()
	h.Write(d)
	return h.Sum(d[:0])
}

// ComputeChecksum returns a four byte checksum computed from the first 21
// bytes of the address.  The embedded checksum is not updated.
func (a *a25) ComputeChecksum() (c [4]byte) {
	copy(c[:], a.doubleSHA256())
	return
}

// Tmpl and Set58 are adapted from the C solution.
// Go has big integers but this technique seems better.
var tmpl = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// Set58 takes a base58 encoded address and decodes it into the receiver.
// Errors are returned if the argument is not valid base58 or if the decoded
// value does not fit in the 25 byte address.  The address is not otherwise
// checked for validity.
func (a *a25) Set58(s []byte) error {
	for _, s1 := range s {
		c := bytes.IndexByte(tmpl, s1)
		if c < 0 {
			return errors.New("bad char")
		}
		for j := 24; j >= 0; j-- {
			c += 58 * int(a[j])
			a[j] = byte(c % 256)
			c /= 256
		}
		if c > 0 {
			return errors.New("too long")
		}
	}
	return nil
}

// verifyByBitCoin verifies bitcoin address based on ValidA58 algorithm
// ValidA58 validates a base58 encoded bitcoin address.  An address is valid
// if it can be decoded into a 25 byte address, the version number is 0,
// and the checksum validates.  Return value ok will be true for valid
// addresses.  If ok is false, the address is invalid.
func (I *Detector) verifyByBitCoin(res *header.DetectResult) bool {
	a58 := []byte(res.Text)
	var a a25
	if err := a.Set58(a58); err != nil {
		return false
	}
	if a.version() != 0 {
		return false
	}
	return a.embeddedChecksum() == a.ComputeChecksum()
}

// verifyByCreditCard verifies credit card
func (I *Detector) verifyByCreditCard(res *header.DetectResult) bool {
	patternText := res.Text
	sanitizedValue := strings.Replace(patternText, "-", "", -1)
	numberLen := len(sanitizedValue)
	sum := 0
	alternate := false

	// length is not matched
	if numberLen < 13 || numberLen > 19 {
		return false
	}

	for i := numberLen - 1; i > -1; i-- {
		mod := int(byte(sanitizedValue[i]) - '0')
		if alternate {
			mod *= 2
			if mod > 9 {
				mod = (mod % 10) + 1
			}
		}
		alternate = !alternate
		sum += mod
	}
	return sum%10 == 0
}

// verifyByABARouting checks whether result is aba routing
func (I *Detector) verifyByABARouting(res *header.DetectResult) bool {
	patternText := res.Text
	sanitizedValue := strings.Replace(patternText, "-", "", -1)
	numberLen := len(sanitizedValue)
	sum := 0
	if numberLen != 9 { // length not match
		return false
	}
	weight := []int{3, 7, 1, 3, 7, 1, 3, 7, 1}
	for i := range weight {
		item := int(byte(sanitizedValue[i]) - '0')
		sum += item * weight[i]
	}
	return sum%10 == 0
}

// verifyByDomain checks whether result is domain
func (I *Detector) verifyByDomain(res *header.DetectResult) bool {
	// Original top-level domains
	// https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains#ICANN-era_generic_top-level_domains
	b64SuffixList := "LmJpenwuY29tfC5vcmd8Lm5ldHwuZWR1fC5nb3Z8LmludHwubWlsfC5hcnBhfC5pbmZvfC5wcm98LmNvb3B8LmFlcm98Lm5" +
		"hbWV8LmlkdnwuY2N8LnR2fC50ZWNofC5tb2JpfC5hY3wuYWR8LmFlfC5hZnwuYWd8LmFpfC5hbHwuYW18LmFvfC5hcXwuYXJ8LmFzfC5hdHw" +
		"uYXV8LmF3fC5heHwuYXp8LmJhfC5iYnwuYmR8LmJlfC5iZnwuYmd8LmJofC5iaXwuYmp8LmJtfC5ibnwuYm98LmJxfC5icnwuYnN8LmJ0fC5" +
		"id3wuYnl8LmJ6fC5jYXwuY2R8LmNmfC5jZ3wuY2h8LmNpfC5ja3wuY2x8LmNtfC5jbnwuY298LmNyfC5jdXwuY3d8LmN4fC5jeXwuY3p8LmR" +
		"lfC5kanwuZGt8LmRtfC5kb3wuZHp8LmVjfC5lZXwuZWd8LmVofC5lcnwuZXN8LmV0fC5ldXwuZml8LmZqfC5ma3wuZm18LmZvfC5mcnwuZ2F" +
		"8LmdkfC5nZXwuZ2Z8LmdnfC5naHwuZ2l8Z2x8LmdtfC5nbnwuZ3B8LmdxfC5ncnwuZ3N8Lmd0fC5ndXwuZ3d8LmhrfC5obXwuaG58LmhyfC5" +
		"odHwuaHV8LmlkfC5pZXwuaWx8LmltfC5pbnwuaW98LmlxfC5pcnwuaXN8Lml0fC5qZXwuam18LmpvfC5qcHwua2V8LmtnfC5raHwua3J8Lmt" +
		"3fC5reXwua3p8LmxhfC5sYnwubGN8LmxpfC5sa3wubHJ8LmxzfC5sdHwubHV8Lmx2fC5seXwubWF8Lm1jfC5tZHwubWV8Lm1nfC5taHwubWt" +
		"8Lm1sfC5tbXwubW58Lm1vfC5tcHwubXF8Lm1yfC5tc3wubXR8Lm11fC5tdnwubXd8Lm14fC5teXwubXp8Lm5hfC5uY3wubmV8Lm5mfC5uZ3w" +
		"ubml8Lm5sfC5ub3wubnB8Lm5yfC5udXwubnp8Lm9tfC5wYXwucGV8LnBmfC5wZ3wucGh8LnBrfC5wbHwucG18LnBufC5wcnwucHN8LnB0fC5" +
		"wd3wucHl8LnFhfC5yZXwucm98LnJzfC5ydXwucnd8LnNhfC5zYnwuc2N8LnNkfC5zZXwuc2d8LnNofC5zaXwuc2t8LnNsfC5zbXwuc258LnN" +
		"vfC5zcnwuc3Z8LnN4fC5zeXwuc3p8LnRjfC50ZHwudGZ8LnRnfC50aHwudGp8LnRrfC50bHwudG18LnRufC50b3wudHJ8LnR0fC50dnwudHd" +
		"8LnR6fHVhfC51Z3wudWt8LnVzfC51eXwudXp8LnZhfC52Y3wudmV8LnZnfC52aXwudm58LnZ1fC53Znwud3N8LnllfC55dHwuemF8LnptfC5" +
		"6dw=="
	suffixData, _ := base64.StdEncoding.DecodeString(b64SuffixList)
	suffixList := bytes.Split(suffixData, []byte("|"))
	matchText := res.Text
	for _, buf := range suffixList {
		word := string(buf)
		if strings.HasSuffix(matchText, word) {
			return true
		}
	}
	return false
}

// getLastKey extracts last key from path
func (I *Detector) getLastKey(path string) (string, bool) {
	sz := len(path)
	if path[sz-1] == ']' { // path likes key[n]
		ed := strings.LastIndexByte(path, '[')
		st := strings.LastIndexByte(path, '/')
		return path[st+1 : ed], true
	} else {
		pos := strings.LastIndexByte(path, '/')
		if pos == -1 {
			return path, false
		} else {
			return path[pos+1:], true
		}
	}
}
