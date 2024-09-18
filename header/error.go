package header

import (
	"errors"
)

var (
	ErrNotReach          = errors.New("[DLP] Code should not reach here")
	ErrHasNotConfigured  = errors.New("[DLP] Engine has not been configured yet, call ApplyConfig* API")
	ErrConfEmpty         = errors.New("[DLP] ConfigString is empty")
	ErrConfURLEmpty      = errors.New("[DLP] ConfigURL is empty")
	ErrConfPathEmpty     = errors.New("[DLP] ConfPath is empty")
	ErrConfVerifyFailed  = errors.New("[DLP] Config verify failed")
	ErrDisableRuleFailed = errors.New("[DLP] Rule is in DisableRules but not found in Rules")
	ErrAuthFailed        = errors.New("[DLP] Authentication Failed")
	ErrRemoteCfgFailed   = errors.New("[DLP] Remote config failed, will load default config")
	ErrProcessAfterClose = errors.New("[DLP] Engine has been closed")
	ErrNewEngineDebug    = errors.
				New("[DLP] NewEngineDebug is only used for debug, register your psm on DLP management system")
	ErrMaxInputLimit        = errors.New("[DLP] Exceed max input limitation")
	ErrPositionError        = errors.New("[DLP] Length of position parameter must be 2")
	ErrRegexNeedString      = errors.New("[DLP] Regex value should be string")
	ErrRegexCompileFailed   = errors.New("[DLP] Regex compile error")
	ErrDictNeedStringArray  = errors.New("[DLP] Dict rule needs string array")
	ErrReEmpty              = errors.New("[DLP] Re object is nil")
	ErrMaskWorkerNotfound   = errors.New("[DLP] Mask worker not found")
	ErrLoadMaskNameConflict = errors.New("[DLP] Load mask rule name conflict")
	ErrPanic                = errors.New("[DLP] Panic in DLP")
	ErrMaskNotSupport       = errors.New("[DLP] Mask Method not support")
	ErrMaskFailed           = errors.New("[DLP] Mask Failed, input is returned")
	ErrMaskTagNotSupport    = errors.New("[DLP] Mask() dose not support with MaskType: Tag, which is used in DeIdentify()")
	ErrMaskNameConflict     = errors.New("[DLP] MaskName conflicts with MaskRules.RuleName")
	ErrMaskRuleNotfound     = errors.New("[DLP] Mask Rule is not Found")
	ErrDataMarshal          = errors.New("[DLP] Data marshal error")
	ErrSendRequest          = errors.New("[DLP] SendRequest error")
	ErrMaskStructInput      = errors.New("[DLP] Input of MaskStruct must be a pointer of a struct")
	ErrMaskStructOutput     = errors.New("[DLP] Internal Error of MaskStruct, output is nil")
	ErrOnlyForLog           = errors.New("[DLP] NewLogProcessor() has been called. engine can be only used for log")
)
