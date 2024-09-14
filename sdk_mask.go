// Package dlp sdk mask.go implements Mask API
package dlp

import (
	"fmt"
	"reflect"

	"github.com/bytedance/godlp/header"
	"github.com/bytedance/godlp/mask"
)

// Mask will return masked text directly based on methodName
func (I *Engine) Mask(inputText string, methodName string) (outputText string, err error) {
	defer I.recoveryImpl()
	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return "", header.ErrProcessAfterClose
	}
	if len(inputText) > DefMaxInput {
		return inputText, fmt.Errorf("DefMaxInput: %d , %w", DefMaxInput, header.ErrMaxInputLimit)
	}
	if maskWorker, ok := I.maskerMap[methodName]; ok {
		return maskWorker.Mask(inputText)
	} else {
		return inputText, fmt.Errorf("methodName: %s, error: %w", methodName, header.ErrMaskWorkerNotfound)
	}
}

// MaskStruct will mask a struct object by tag mask info
// 根据tag mask里定义的脱敏规则对struct object直接脱敏, 会修改obj本身，传入指针，返回指针
func (I *Engine) MaskStruct(inPtr interface{}) (outPtr interface{}, retErr error) {
	outPtr = inPtr                      // fail back to inPtr
	retErr = header.ErrMaskStructOutput // default return err if panic
	defer I.recoveryImpl()
	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return inPtr, header.ErrProcessAfterClose
	}
	if inPtr == nil {
		return nil, header.ErrMaskStructInput
	}
	outPtr, retErr = I.maskStructImpl(inPtr, DefMaxCallDeep)
	return
}

// RegisterMasker Register DIY Masker
// 注册自定义打码函数
func (I *Engine) RegisterMasker(maskName string, maskFunc func(string) (string, error)) error {
	defer I.recoveryImpl()
	if !I.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if I.hasClosed() {
		return header.ErrProcessAfterClose
	}
	if _, ok := I.maskerMap[maskName]; ok {
		return header.ErrMaskNameConflict
	} else {
		if worker, err := I.NewDIYMaskWorker(maskName, maskFunc); err == nil {
			I.maskerMap[maskName] = worker
			return nil
		} else {
			return err
		}
	}
}

// private func

// DIYMaskWorker stores maskFuc and maskName
type DIYMaskWorker struct {
	maskFunc func(string) (string, error)
	maskName string
}

// GetRuleName is required by mask.API
func (I *DIYMaskWorker) GetRuleName() string {
	return I.maskName
}

// Mask is required by mask.API
func (I *DIYMaskWorker) Mask(in string) (string, error) {
	return I.maskFunc(in)
}

// MaskResult is required by mask.API
func (I *DIYMaskWorker) MaskResult(res *header.DetectResult) error {
	if out, err := I.Mask(res.Text); err == nil {
		res.MaskText = out
		return nil
	} else {
		return err
	}
}

// NewDIYMaskWorker creates mask.API object
func (I *Engine) NewDIYMaskWorker(maskName string, maskFunc func(string) (string, error)) (mask.API, error) {
	worker := new(DIYMaskWorker)
	worker.maskName = maskName
	worker.maskFunc = maskFunc
	return worker, nil
}

// maskStructImpl will mask a struct object by tag mask info
// 根据tag mask里定义的脱敏规则对struct object直接脱敏, 会修改obj本身，传入指针，返回指针
func (I *Engine) maskStructImpl(inPtr interface{}, level int) (interface{}, error) {
	// logger.Errorf("[DLP] level:%d, maskStructImpl: %+v", level, inPtr)
	if level <= 0 { // call deep check
		// logger.Errorf("[DLP] !call deep loop detected!")
		// logger.Errorf("obj: %+v", inPtr)
		return inPtr, nil
	}
	valPtr := reflect.ValueOf(inPtr)
	if valPtr.Kind() != reflect.Ptr || valPtr.IsNil() || !valPtr.IsValid() || valPtr.IsZero() {
		return inPtr, header.ErrMaskStructInput
	}
	val := reflect.Indirect(valPtr)
	var retErr error
	if val.CanSet() {
		if val.Kind() == reflect.Struct {
			sz := val.NumField()
			if sz > DefMaxInput {
				return inPtr, fmt.Errorf("DefMaxInput: %d , %w", DefMaxInput, header.ErrMaxInputLimit)
			}
			for i := 0; i < sz; i++ {
				valField := val.Field(i)
				typeField := val.Type().Field(i)
				inStr := valField.String()
				outStr := inStr // default is original str
				methodName, ok := typeField.Tag.Lookup("mask")
				if !ok { // mask tag not found
					continue
				}
				if valField.CanSet() {
					switch valField.Kind() {
					case reflect.String:
						if len(methodName) > 0 {
							if maskWorker, ok := I.maskerMap[methodName]; ok {
								if masked, err := maskWorker.Mask(inStr); err == nil {
									outStr = masked
									valField.SetString(outStr)
								}
							}
						}
					case reflect.Struct:
						if valField.CanAddr() {
							// logger.Errorf("[DLP] Struct, %s", typeField.Name)
							_, retErr = I.maskStructImpl(valField.Addr().Interface(), level-1)
						}
					case reflect.Ptr:
						if !valField.IsNil() {
							// logger.Errorf("[DLP] Ptr, %s", typeField.Name)
							_, retErr = I.maskStructImpl(valField.Interface(), level-1)
						}
					case reflect.Interface:
						if valField.CanInterface() {
							valInterFace := valField.Interface()
							if inStr, ok := valInterFace.(string); ok {
								outStr := inStr
								if len(methodName) > 0 {
									if maskWorker, ok := I.maskerMap[methodName]; ok {
										if masked, err := maskWorker.Mask(inStr); err == nil {
											outStr = masked
											if valField.CanSet() {
												valField.Set(reflect.ValueOf(outStr))
											}
										}
									}
								}
							}
						}
					case reflect.Slice, reflect.Array:
						length := valField.Len()
						for i := 0; i < length; i++ {
							item := valField.Index(i)
							if item.Kind() == reflect.String {
								inStr := item.String()
								outStr := inStr
								// use parent mask info
								if len(methodName) > 0 {
									if maskWorker, ok := I.maskerMap[methodName]; ok {
										if masked, err := maskWorker.Mask(inStr); err == nil {
											outStr = masked
											if item.CanSet() {
												item.SetString(outStr)
											}
										}
									}
								}
							} else if item.Kind() == reflect.Ptr {
								if !item.IsNil() {
									// logger.Errorf("[DLP] Ptr, %s", item.Type().Name())
									_, retErr = I.maskStructImpl(item.Interface(), level-1)
								}
							} else if item.Kind() == reflect.Struct {
								if item.CanAddr() {
									// logger.Errorf("[DLP] Struct, %s", item.Type().Name())
									_, retErr = I.maskStructImpl(item.Addr().Interface(), level-1)
								}
							}
						}
					default:
						continue
					}
				}
			}
		}
	}
	return inPtr, retErr
}
