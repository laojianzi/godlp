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

	"github.com/laojianzi/godlp/conf"
	"github.com/laojianzi/godlp/header"
)

// RuleType is different with ResultType, because for input string contains KV object,
// KV rule will generate Value Detect Type
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
func (d *Detector) GetRuleInfo() string {
	return fmt.Sprintf("%+v", d.rule)
}

// GetRuleID returns RuleID
func (d *Detector) GetRuleID() int32 {
	return d.rule.RuleID
}

// GetMaskRuleName returns MaskRuleName used in Detect Rule
func (d *Detector) GetMaskRuleName() string {
	return d.rule.Mask
}

// IsValue checks whether Detect RuleType is VALUE
func (d *Detector) IsValue() bool {
	return d.RuleType == RuleTypeValue
}

// IsKV checks whether Detect RuleType is KV
func (d *Detector) IsKV() bool {
	return d.RuleType == RuleTypeKv
}

// UseRegex checks whether Rule use Regex
func (d *Detector) UseRegex() bool {
	return len(d.KReg) > 0 || len(d.VReg) > 0
}

// DetectBytes detects sensitive info for bytes, is called from Detect()
func (d *Detector) DetectBytes(inputBytes []byte) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0, DefResultSize)
	for _, reObj := range d.VReg {
		if ret, err := d.regexDetectBytes(reObj, inputBytes); err == nil {
			results = append(results, ret...)
			if len(ret) > 0 && d.rule.InfoType == header.ADDRESS { // Avoid duplicate address types
				break
			}

			continue
		}

		// logger.Errorf(err.Error())
	}
	for _, item := range d.VDict {
		if ret, err := d.dictDetectBytes([]byte(item), inputBytes); err == nil {
			results = append(results, ret...)
			continue
		}

		// logger.Errorf(err.Error())
	}
	results = d.filter(results)
	results = d.verify(inputBytes, results)
	return results, nil
}

// DetectMap detects for Map, is called from DetectMap() and DetectJSON()
func (d *Detector) DetectMap(inputMap map[string]string) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0)

	// (KReg || KDict) && (VReg || VDict)
	item := &KVItem{Start: 0, End: 0}
	for inK, inV := range inputMap {
		item.Key = inK
		item.Value = inV
		d.doDetectKV(item, &results)
	}

	return d.filter(results), nil
}

// DetectList detects for List
func (d *Detector) DetectList(kvList []*KVItem) ([]*header.DetectResult, error) {
	results := make([]*header.DetectResult, 0)

	length := len(kvList)
	for i := 0; i < length; i++ {
		d.doDetectKV(kvList[i], &results)
	}

	return d.filter(results), nil
}

func (d *Detector) doDetectKV(kvItem *KVItem, results *[]*header.DetectResult) {
	// inK may be a path of json object
	lastKey, ifExtracted := d.getLastKey(kvItem.Key)
	resultType := ResultTypeValue
	if d.IsKV() { // nolint: nestif
		// key rules check
		// Dict rules first, then regex rule
		_, hit := d.KDict[lastKey]
		if (!hit) && ifExtracted {
			_, hit = d.KDict[kvItem.Key]
		}

		if !hit {
			for _, re := range d.KReg {
				if re.Match([]byte(lastKey)) {
					hit = true
					break
				}
			}
		}

		if !hit {
			return
		}

		// key rule is hit
		if len(d.VDict) == 0 && len(d.VReg) == 0 { // no value rule
			if res, err := d.createKVResult(kvItem.Key, kvItem.Value); err == nil {
				res.ByteStart += kvItem.Start
				res.ByteEnd += kvItem.Start
				*results = append(*results, d.verify([]byte(kvItem.Value), []*header.DetectResult{res})...)
			}

			return
		}

		resultType = ResultTypeKv
	}

	vResults, err := d.DetectBytes([]byte(kvItem.Value))
	if err != nil {
		return
	}

	vNewResults := make([]*header.DetectResult, len(vResults))
	for i, res := range vResults {
		res.ResultType = resultType
		res.Key = kvItem.Key
		res.ByteStart += kvItem.Start
		res.ByteEnd += kvItem.Start
		vNewResults[i] = res
	}

	*results = append(*results, d.verify([]byte(kvItem.Value), vNewResults)...)
}

// Close release detector object
func (d *Detector) Close() {
	for i := range d.VReg {
		d.VReg[i] = nil
	}
	// Detect section
	d.KDict = nil
	d.releaseReg(d.KReg)
	d.KReg = nil
	d.VDict = nil
	d.releaseReg(d.VReg)
	d.VReg = nil

	// Filter section
	d.BAlgo = nil
	d.BDict = nil
	d.releaseReg(d.BReg)
	d.BReg = nil

	// Verify section
	d.CDict = nil
	d.releaseReg(d.CReg)
	d.CReg = nil
	d.VAlgo = nil
}

// private func

// prepare will prepare detector object from rule
func (d *Detector) prepare() {
	// Detect
	d.KReg = d.preCompile(d.rule.Detect.KReg)
	d.KDict = lowerStringList2Map(d.rule.Detect.KDict)
	d.VReg = d.preCompile(d.rule.Detect.VReg)
	d.VDict = d.rule.Detect.VDict

	// Filter
	d.BReg = d.preCompile(d.rule.Filter.BReg)
	d.BAlgo = d.rule.Filter.BAlgo
	d.BDict = d.rule.Filter.BDict
	// Verify
	d.CReg = d.preCompile(d.rule.Verify.CReg)
	d.CDict = d.rule.Verify.CDict
	d.VAlgo = d.rule.Verify.VAlgo
	d.setRuleType()
}

// setRuleType set RuleType based on K V in detect section of config
func (d *Detector) setRuleType() {
	if len(d.KDict) == 0 && len(d.KReg) == 0 { // no key rules means RuleType is VALUE
		d.RuleType = RuleTypeValue
	} else { // RuleType is KV
		d.RuleType = RuleTypeKv
	}
}

// releaseReg will set item of list as nil
func (d *Detector) releaseReg(list []*regexp.Regexp) {
	for i := range list {
		list[i] = nil
	}
}

// preCompile compiles regex string list then return regex list
func (d *Detector) preCompile(reList []string) []*regexp.Regexp {
	list := make([]*regexp.Regexp, 0, DefResultSize)
	for _, reStr := range reList {
		if re, err := regexp.Compile(reStr); err == nil {
			list = append(list, re)
			continue
		}

		// logger.Errorf("Regex %s ,error: %w", reStr, err)
	}
	return list
}

// preToLower modify dictList to lower case
//
// //nolint: unused
func (d *Detector) preToLower(dictList []string) []string {
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
func (d *Detector) regexDetectBytes(re *regexp.Regexp, inputBytes []byte) ([]*header.DetectResult, error) {
	if re == nil {
		return nil, header.ErrReEmpty
	}
	results := make([]*header.DetectResult, 0, DefResultSize)
	if ret := re.FindAllIndex(inputBytes, -1); ret != nil {
		for i := range ret {
			pos := ret[i]
			if res, err := d.createValueResult(inputBytes, pos); err == nil {
				results = append(results, res)
			}
		}
	}
	return results, nil
}

// dictDetectBytes finds whether word in input bytes
func (d *Detector) dictDetectBytes(word []byte, inputBytes []byte) ([]*header.DetectResult, error) {
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
			if res, err := d.createValueResult(inputBytes, pos); err == nil {
				results = append(results, res)
			}
			current = inputBytes[end:]
			currStart = end
		}
	}
	return results, nil
}

// createValueResult creates value result item
func (d *Detector) createValueResult(inputBytes []byte, pos []int) (ret *header.DetectResult, err error) {
	if len(pos) != 2 {
		return nil, header.ErrPositionError
	}
	ret = d.newResult()
	ret.Text = string(inputBytes[pos[0]:pos[1]])
	ret.ResultType = ResultTypeValue
	ret.ByteStart = pos[0]
	ret.ByteEnd = pos[1]
	return ret, nil
}

// createKVResult creates kv result
func (d *Detector) createKVResult(inK string, inV string) (*header.DetectResult, error) {
	ret := d.newResult()
	ret.Text = inV
	ret.ResultType = ResultTypeKv
	ret.ByteStart = 0
	ret.ByteEnd = len(inV)
	ret.Key = inK
	return ret, nil
}

// newResult new result
func (d *Detector) newResult() *header.DetectResult {
	ret := new(header.DetectResult)
	ret.RuleID = d.rule.RuleID
	ret.InfoType = d.rule.InfoType
	ret.EnName = d.rule.EnName
	ret.CnName = d.rule.CnName
	ret.ExtInfo = d.rule.ExtInfo
	ret.Level = d.rule.Level
	return ret
}

// filter will process filter condition
func (d *Detector) filter(in []*header.DetectResult) []*header.DetectResult {
	out := make([]*header.DetectResult, 0, DefResultSize)
	for i := range in {
		res := in[i]
		if d.filterBDict(res.Text) || d.filterBReg(res.Text) || d.filterBAlgo(res.Text) {
			continue
		}

		out = append(out, res)
	}

	return out
}

func (d *Detector) filterBDict(text string) bool {
	for _, word := range d.BDict {
		// Found in BlackList BDict
		if strings.Compare(text, word) == 0 {
			return true
		}
	}

	return false
}

func (d *Detector) filterBReg(text string) bool {
	for _, re := range d.BReg {
		// Found in BlackList BReg
		if re.Match([]byte(text)) {
			return true
		}
	}

	return false
}

func (d *Detector) filterBAlgo(text string) bool {
	for _, algo := range d.BAlgo {
		switch algo {
		case BlacklistAlgoMasked:
			if IsMasked(text) {
				return true
			}
		}
	}

	return false
}

// IsMasked checks input whether contain * or #
func IsMasked(in string) bool {
	pos := strings.IndexAny(in, MaskedCharList)
	return pos != -1 // found mask char
}

// verify use verify config to check results
func (d *Detector) verify(inputBytes []byte, in []*header.DetectResult) []*header.DetectResult {
	out := make([]*header.DetectResult, 0, DefResultSize)
	markList := make([]bool, len(in))
	for i := range markList {
		markList[i] = true
	}

	if len(d.CDict) != 0 || len(d.CReg) != 0 { // need context check
		for i, res := range in {
			if !d.verifyByContext(inputBytes, res) { // check failed
				markList[i] = false
			}
		}
	}

	if len(d.VAlgo) != 0 {
		// need verify algorithm check
		d.verifyAlgo(in, markList)
	}

	for i, need := range markList {
		if need {
			out = append(out, in[i])
		}
	}

	return out
}

// verifyAlgo verify algorithm check
func (d *Detector) verifyAlgo(in []*header.DetectResult, markList []bool) []bool {
	for i, res := range in {
		if !markList[i] {
			continue
		}

		for _, algo := range d.VAlgo {
			switch algo {
			case VerifyAlgoIDCard:
				if !d.verifyByIDCard(res) { // check failed
					markList[i] = false
				}
			case VerifyAlgoAbaRouting:
				if !d.verifyByABARouting(res) {
					markList[i] = false
				}
			case VerifyAlgoCreditCard:
				if !d.verifyByCreditCard(res) {
					markList[i] = false
				}
			case VerifyAlgoBitcoin:
				if !d.verifyByBitCoin(res) {
					markList[i] = false
				}
			case VerifyAlgoDomain:
				if !d.verifyByDomain(res) {
					markList[i] = false
				}
			}
		}
	}

	return markList
}

// verifyByContext check around context to decide whether res is accuracy
func (d *Detector) verifyByContext(inputBytes []byte, res *header.DetectResult) bool {
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
	for _, word := range d.CDict {
		if len(word) == 0 {
			continue
		}
		wordBytes := []byte(strings.ToLower(word))
		pos := bytes.Index(subInput, wordBytes)
		for start := 0; pos != -1; pos = bytes.Index(subInput[start:], wordBytes) {
			if d.isWholeWord(subInput[start:], wordBytes, pos) {
				return true
			}
			start += pos + len(word)
		}
	}

	var found bool
	for _, re := range d.CReg {
		if re.Match(subInput) {
			found = true
			break
		}
	}

	return found
}

// isWholeWord checks whether word which is found in input is a whole word
func (d *Detector) isWholeWord(in []byte, word []byte, pos int) bool {
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
		}

		return !d.isLetter(right)
	}

	if rightSz == 0 {
		return !d.isLetter(left)
	}

	return !d.isLetter(left) && !d.isLetter(right)
}

// isLetter checks whether r is a-zA-z
func (d *Detector) isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// verifyByIDCard checks whether result is IDCard
func (d *Detector) verifyByIDCard(res *header.DetectResult) bool {
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
func (d *Detector) verifyByBitCoin(res *header.DetectResult) bool {
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
func (d *Detector) verifyByCreditCard(res *header.DetectResult) bool {
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
func (d *Detector) verifyByABARouting(res *header.DetectResult) bool {
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
func (d *Detector) verifyByDomain(res *header.DetectResult) bool {
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
func (d *Detector) getLastKey(path string) (string, bool) {
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
