// Package dlp sdk mask.go implements Mask API
package dlp

import (
	"fmt"
	"reflect"

	"github.com/laojianzi/godlp/header"
	"github.com/laojianzi/godlp/mask"
)

// Mask will return masked text directly based on methodName
func (e *Engine) Mask(inputText string, methodName string) (outputText string, err error) {
	defer e.recoveryImpl()
	if !e.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if e.hasClosed() {
		return "", header.ErrProcessAfterClose
	}
	if len(inputText) > DefMaxInput {
		return inputText, fmt.Errorf("DefMaxInput: %d , %w", DefMaxInput, header.ErrMaxInputLimit)
	}
	if maskWorker, ok := e.maskerMap[methodName]; ok {
		return maskWorker.Mask(inputText)
	} else {
		return inputText, fmt.Errorf("methodName: %s, error: %w", methodName, header.ErrMaskWorkerNotfound)
	}
}

// MaskStruct will mask a struct object by tag mask info
// 根据tag mask里定义的脱敏规则对struct object直接脱敏, 会修改obj本身，传入指针，返回指针
func (e *Engine) MaskStruct(inPtr interface{}) (outPtr interface{}, retErr error) {
	defer e.recoveryImpl()

	outPtr = inPtr                      // fail back to inPtr
	retErr = header.ErrMaskStructOutput // default return err if panic

	if !e.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}

	if e.hasClosed() {
		return inPtr, header.ErrProcessAfterClose
	}

	if inPtr == nil {
		return nil, header.ErrMaskStructInput
	}

	outPtr, retErr = e.maskStructImpl(inPtr, DefMaxCallDeep)
	return
}

// RegisterMasker Register DIY Masker
// 注册自定义打码函数
func (e *Engine) RegisterMasker(maskName string, maskFunc func(string) (string, error)) error {
	defer e.recoveryImpl()
	if !e.hasConfigured() { // not configured
		panic(header.ErrHasNotConfigured)
	}
	if e.hasClosed() {
		return header.ErrProcessAfterClose
	}
	if _, ok := e.maskerMap[maskName]; ok {
		return header.ErrMaskNameConflict
	} else {
		if worker, err := e.NewDIYMaskWorker(maskName, maskFunc); err == nil {
			e.maskerMap[maskName] = worker
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
func (d *DIYMaskWorker) GetRuleName() string {
	return d.maskName
}

// Mask is required by mask.API
func (d *DIYMaskWorker) Mask(in string) (string, error) {
	return d.maskFunc(in)
}

// MaskResult is required by mask.API
func (d *DIYMaskWorker) MaskResult(res *header.DetectResult) error {
	if out, err := d.Mask(res.Text); err == nil {
		res.MaskText = out
		return nil
	} else {
		return err
	}
}

// NewDIYMaskWorker creates mask.API object
func (e *Engine) NewDIYMaskWorker(maskName string, maskFunc func(string) (string, error)) (mask.API, error) {
	worker := new(DIYMaskWorker)
	worker.maskName = maskName
	worker.maskFunc = maskFunc
	return worker, nil
}

// maskStructImpl will mask a struct object by tag mask info
// 根据tag mask里定义的脱敏规则对struct object直接脱敏, 会修改obj本身，传入指针，返回指针
func (e *Engine) maskStructImpl(inPtr interface{}, level int) (interface{}, error) {
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
	if !val.CanSet() {
		return inPtr, nil
	}

	if val.Kind() != reflect.Struct {
		return inPtr, nil
	}

	sz := val.NumField()
	if sz > DefMaxInput {
		return inPtr, fmt.Errorf("DefMaxInput: %d , %w", DefMaxInput, header.ErrMaxInputLimit)
	}

	for i := 0; i < sz; i++ {
		valField := val.Field(i)
		typeField := val.Type().Field(i)
		if err := e.maskStructField(valField, typeField, level); err != nil {
			return nil, err
		}
	}

	return inPtr, nil
}

// maskStructField will mask a struct field by tag mask info
func (e *Engine) maskStructField(valField reflect.Value, typeField reflect.StructField, level int) error {
	methodName, ok := typeField.Tag.Lookup("mask")
	if !ok { // mask tag not found
		return nil
	}

	if !valField.CanSet() {
		return nil
	}

	switch valField.Kind() {
	case reflect.String:
		return e.maskTypeString(methodName, valField)
	case reflect.Struct:
		return e.maskTypeStruct(valField, level)
	case reflect.Ptr:
		return e.maskTypePtr(valField, level)
	case reflect.Interface:
		return e.maskTypeInterface(methodName, valField)
	case reflect.Slice, reflect.Array:
		return e.maskTypeList(methodName, valField, level)
	default:
	}

	return nil
}

func (e *Engine) maskTypeString(methodName string, valField reflect.Value) error {
	if len(methodName) <= 0 {
		return nil
	}

	if maskWorker, ok := e.maskerMap[methodName]; ok {
		if masked, err := maskWorker.Mask(valField.String()); err == nil {
			if valField.CanSet() {
				valField.SetString(masked)
			}
		}
	}

	return nil
}

func (e *Engine) maskTypeStruct(valField reflect.Value, level int) error {
	if valField.CanAddr() {
		// logger.Errorf("[DLP] Struct, %s", typeField.Name)
		_, err := e.maskStructImpl(valField.Addr().Interface(), level-1)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Engine) maskTypePtr(valField reflect.Value, level int) error {
	if !valField.IsNil() {
		// logger.Errorf("[DLP] Ptr, %s", typeField.Name)
		_, err := e.maskStructImpl(valField.Interface(), level-1)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Engine) maskTypeInterface(methodName string, valField reflect.Value) error {
	if !valField.CanInterface() {
		return nil
	}

	valInterFace := valField.Interface()
	inStr, ok := valInterFace.(string)
	if !ok || len(methodName) <= 0 {
		return nil
	}

	if maskWorker, ok := e.maskerMap[methodName]; ok {
		if masked, err := maskWorker.Mask(inStr); err == nil {
			if valField.CanSet() {
				valField.Set(reflect.ValueOf(masked))
			}
		}
	}

	return nil
}

func (e *Engine) maskTypeList(methodName string, valField reflect.Value, level int) error {
	length := valField.Len()
	for j := 0; j < length; j++ {
		item := valField.Index(j)
		switch item.Kind() {
		case reflect.String:
			if err := e.maskTypeString(methodName, item); err != nil {
				return err
			}
		case reflect.Ptr:
			if err := e.maskTypePtr(item, level); err != nil {
				return err
			}
		case reflect.Struct:
			if item.CanAddr() {
				// logger.Errorf("[DLP] Struct, %s", item.Type().Name())
				_, err := e.maskStructImpl(item.Addr().Interface(), level-1)
				if err != nil {
					return err
				}
			}
		default:
			continue
		}
	}

	return nil
}
