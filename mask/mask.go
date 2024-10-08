// Package mask implements Mask API
package mask

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"strings"
	"unicode/utf8"

	"github.com/laojianzi/godlp/conf"
	"github.com/laojianzi/godlp/header"
)

const (
	TypeChar    = "CHAR"    // 用字符替换敏感信息，需要用到后面更详细的配置项。
	TypeTag     = "TAG"     // 用识别和处理规则中的InfoType, 以`<InfoType>`的形式替换敏感信息。
	TypeReplace = "REPLACE" // 用Value定义的字符串，替换敏感信息，可以设定为空串，用于直接抹除。
	TypeAlgo    = "ALGO"    // 用Value定义的算法函数，处理敏感信息，用算法返回值替换原文，目前支持的算法有 [BASE64, MD5, CRC32]

	TypeAlgoBase64 = "BASE64"
	TypeAlgoMd5    = "MD5"
	TypeAlgoCrc32  = "CRC32"

	TypeUnknown = "UNKNOWN"
)

type Worker struct {
	rule   conf.MaskRuleItem
	parent header.EngineAPI
}

type API interface {
	// GetRuleName return RuleName of a Worker
	// 返回RuleName
	GetRuleName() string
	// Mask will return masked string
	// 返回打码后的文本
	Mask(in string) (string, error)
	// MaskResult will modify DetectResult.MaskText
	// 修改DetectResult.MaskText
	MaskResult(res *header.DetectResult) error
}

// NewWorker create Worker based on MaskRule
func NewWorker(rule conf.MaskRuleItem, p header.EngineAPI) (API, error) {
	obj := new(Worker)
	// IgnoreKind
	for _, kind := range rule.IgnoreKind {
		switch kind {
		case "NUMERIC":
			rule.IgnoreCharSet += "0123456789"
		case "ALPHA_LOWER_CASE":
			rule.IgnoreCharSet += "abcdefghijklmnopqrstuvwxyz"
		case "ALPHA_UPPER_CASE":
			rule.IgnoreCharSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		case "WHITESPACE":
			rule.IgnoreCharSet += " \t\n\x0B\f\r"
		case "PUNCTUATION":
			rule.IgnoreCharSet += "!\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"
		}
	}
	obj.rule = rule
	obj.parent = p
	return obj, nil
}

// GetRuleName return RuleName of a Worker
// 返回RuleName
func (I *Worker) GetRuleName() string {
	return I.rule.RuleName
}

// MaskResult will modify DetectResult.MaskText
// 修改DetectResult.MaskText
func (I *Worker) MaskResult(res *header.DetectResult) error {
	var err error
	if strings.Compare(I.rule.MaskType, TypeTag) == 0 {
		res.MaskText, err = I.maskTagImpl(res.Text, res.InfoType)
	} else {
		res.MaskText, err = I.Mask(res.Text)
	}
	return err
}

// Mask will return masked string
// 返回打码后的文本
func (I *Worker) Mask(in string) (string, error) {
	out := in
	err := fmt.Errorf("RuleName: %s, MaskType: %s , %w", I.rule.RuleName, I.rule.MaskType, header.ErrMaskNotSupport)
	switch I.rule.MaskType {
	case TypeChar:
		out, err = I.maskCharImpl(in)
	case TypeTag:
		out, err = I.maskStrTagImpl(in)
	case TypeReplace:
		out, err = I.maskReplaceImpl(in)
	case TypeAlgo:
		out, err = I.maskAlgoImpl(in)
	}
	return out, err
}

// base64
const (
	enterListRes = "6KGX6YGTfOi3r3zooZd86YeMfOadkXzplYd85bGvfOe7hAo="
	midListRes   = "56S+5Yy6fOWwj+WMunzlpKfljqZ85bm/5Zy6fOWPt+alvHzljZXlhYN85Y+3fOWxgnzlrqR85oi3Cg=="
)

var (
	enterList = loadResList(enterListRes)
	midList   = loadResList(midListRes)
)

// loadResList accepts base64 string, then convert them to string list
func loadResList(res string) []string {
	var retList []string
	if decode, err := base64.StdEncoding.DecodeString(res); err == nil {
		trim := strings.TrimSpace(string(decode))
		retList = strings.Split(trim, "|")
	}
	return retList
}

// maskCharImpl mask in string with char
func (I *Worker) maskCharImpl(in string) (string, error) {
	ch := byte('*') // default
	if len(I.rule.Value) > 0 {
		ch = I.rule.Value[0]
	}

	sz := len(in)
	out := []byte(in)
	if !I.rule.Reverse { // nolint: nestif
		cnt, st := 0, 0
		if I.rule.Offset >= 0 {
			st = int(I.rule.Offset)
		}

		ed := sz
		if I.rule.Padding >= 0 {
			ed = sz - int(I.rule.Padding)
		}

		for i := st; i < ed; i++ {
			// if Length == 0 , do not check
			if I.rule.Length > 0 && cnt >= int(I.rule.Length) {
				break
			}

			if strings.IndexByte(I.rule.IgnoreCharSet, out[i]) == -1 { // ignore check
				out[i] = ch
			}

			cnt++
		}
	} else {
		cnt, ed := 0, sz
		if I.rule.Offset >= 0 {
			ed = sz - 1 - int(I.rule.Offset)
		}

		st := 0
		if I.rule.Padding >= 0 {
			st = int(I.rule.Padding)
		}

		for i := ed; i >= st; i-- {
			if I.rule.Length > 0 && cnt >= int(I.rule.Length) {
				break
			}

			if strings.IndexByte(I.rule.IgnoreCharSet, out[i]) == -1 { // ignore check
				out[i] = ch
			}

			cnt++
		}
	}
	return string(out), nil
}

// maskTagImpl mask with the tag of in string
func (I *Worker) maskTagImpl(_ string, infoType string) (string, error) {
	return fmt.Sprintf("<%s>", infoType), nil
}

// maskReplaceImpl replace with rule.Value
func (I *Worker) maskReplaceImpl(_ string) (string, error) {
	return I.rule.Value, nil
}

// maskStrTagImpl first DeIdentify to get info type, then mask with info type
func (I *Worker) maskStrTagImpl(in string) (string, error) {
	if results, err := I.parent.Detect(in); err == nil {
		if len(results) > 0 {
			res := results[0]
			return I.maskTagImpl(in, res.InfoType)
		}
	}
	return I.maskTagImpl(in, TypeUnknown)
}

// maskAlgoImpl replace with algo(in)
func (I *Worker) maskAlgoImpl(in string) (string, error) {
	inBytes := []byte(in)
	switch I.rule.Value {
	case "BASE64":
		return base64.StdEncoding.EncodeToString(inBytes), nil
	case "MD5":
		return fmt.Sprintf("%x", md5.Sum(inBytes)), nil
	case "CRC32":
		return fmt.Sprintf("%08x", crc32.ChecksumIEEE(inBytes)), nil
	case "ADDRESS":
		return I.maskAddressImpl(in)
	case "NUMBER":
		return I.maskNumberImpl(in)
	case "DEIDENTIFY":
		return I.maskDeIdentifyImpl(in)
	default:
		return in, fmt.Errorf("RuleName: %s, MaskType: %s , Value:%s, %w",
			I.rule.RuleName, I.rule.MaskType, I.rule.Value, header.ErrMaskNotSupport)
	}
}

// maskAddressImpl masks Address
func (I *Worker) maskAddressImpl(in string) (string, error) {
	st := 0
	if pos, id := I.indexSubList(in, st, enterList, true); pos != -1 { // found
		st = pos + len(enterList[id])
	}

	out := in[:st]
	sz := len(in)
	for pos, id := I.indexSubList(in, st, midList, false); pos != -1 &&
		st < sz; pos, id = I.indexSubList(in, st, midList, false) {
		out += strings.Repeat("*", pos-st)
		out += midList[id]
		st = pos + len(midList[id])
	}

	out += in[st:]
	out, _ = I.maskNumberImpl(out)
	if strings.Compare(in, out) == 0 { // mask Last 3 rune
		lastByteSz := 0
		for totalRune := 3; totalRune > 0 && len(out) > 0; totalRune-- {
			_, width := utf8.DecodeLastRuneInString(out)
			lastByteSz += width
			out = out[0 : len(out)-width]
		}

		out += strings.Repeat("*", lastByteSz)
	}

	return out, nil
}

// IndexSubList find index of a list of sub strings from a string
func (I *Worker) indexSubList(in string, st int, list []string, isLast bool) (int, int) {
	tmp := in[st:]
	retPos := -1
	retId := -1
	for i, word := range list {
		pos := strings.Index(tmp, word)
		if pos == -1 { // not found
			continue
		}

		loc := st + pos
		if retPos == -1 { // first
			retPos = loc
			retId = i
			if !isLast { // not last return directly
				return retPos, retId
			}
		} else if isLast && loc >= retPos {
			retPos = loc
			retId = i
		}
	}
	return retPos, retId
}

// maskNumberImpl will mask all number in the string
func (I *Worker) maskNumberImpl(in string) (string, error) {
	outBytes := []byte(in)
	for i, ch := range outBytes {
		if ch >= '0' && ch <= '9' {
			outBytes[i] = '*'
		}
	}
	return string(outBytes), nil
}

func (I *Worker) maskDeIdentifyImpl(in string) (string, error) {
	out, _, err := I.parent.DeIdentify(in)
	return out, err
}
