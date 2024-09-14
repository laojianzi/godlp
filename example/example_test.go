package example_test

import (
	"fmt"
	"strings"

	"github.com/bytedance/godlp"
	"github.com/bytedance/godlp/header"
	"github.com/bytedance/godlp/internal/json"
	"github.com/bytedance/godlp/logger"
)

func Example() {
	logger.SetLogger(&exampleLogger{})
	caller := "replace.your.caller"
	// 使用时请将NewEngine()放到循环外，每个线程独立一个Engine Object
	// remove NewEngine() outside for loop, and one Engine Object one thread/goroutine
	if eng, err := dlp.NewEngine(caller); err == nil {
		if err = eng.ApplyConfigDefault(); err != nil {
			panic(err)
		}

		logger.Debugf("DLP %s Demo:\n\n", eng.GetVersion())
		inStr := `我的邮件是abcd@abcd.com,
18612341234是我的电话
你家住在哪里啊? 我家住在北京市海淀区北三环西路43号,
mac地址 06-06-06-aa-bb-cc
收件人：张真人  手机号码：18612341234`
		if results, err := eng.Detect(inStr); err == nil {
			logger.Debugf("\t1. Detect( inStr: %s )\n", inStr)
			eng.ShowResults(results)
		}
		if outStr, _, err := eng.DeIdentify(inStr); err == nil {
			logger.Debugf("\t2. DeIdentify( inStr: %s )\n", inStr)
			logger.Debugf("\toutStr: %s\n", outStr)
			// eng.ShowResults(results)
			logger.Debugf("\n")
		}
		inStr = `18612341234`
		if outStr, err := eng.Mask(inStr, header.CHINAPHONE); err == nil {
			logger.Debugf("\t3. Mask( inStr: %s )\n", inStr)
			logger.Debugf("\toutStr: %s\n", outStr)
			logger.Debugf("\n")
		}

		inMap := map[string]string{"nothing": "nothing", "uid": "10086", "k1": "my phone is 18612341234 and 18612341234"} // extract KV?

		if results, err := eng.DetectMap(inMap); err == nil {
			logger.Debugf("\t4. DetectMap( inMap: %+v )\n", inMap)
			eng.ShowResults(results)
		}

		logger.Debugf("\t5. DeIdentifyMap( inMap: %+v )\n", inMap)
		if outMap, results, err := eng.DeIdentifyMap(inMap); err == nil {
			logger.Debugf("\toutMap: %+v\n", outMap)
			eng.ShowResults(results)
			logger.Debugf("\n")
		}

		inJSON := `{"objList":[{"uid":"10086"},{"uid":"[\"aaaa\",\"bbbb\"]"}]}`

		if results, err := eng.DetectJSON(inJSON); err == nil {
			logger.Debugf("\t6. DetectJSON( inJSON: %s )\n", inJSON)
			eng.ShowResults(results)

			if outJSON, err := eng.DeIdentifyJSONByResult(inJSON, results); err == nil {
				resultsContent, _ := json.Marshal(results)
				logger.Debugf("\t7. DeIdentifyJSONByResult( inJSON: %s , results: %v )\n", inJSON, string(resultsContent))
				logger.Debugf("\toutJSON: %s\n", outJSON)
				eng.ShowResults(results)
				logger.Debugf("\n")
			}
		}

		if outJSON, results, err := eng.DeIdentifyJSON(inJSON); err == nil {
			logger.Debugf("\t7. DeIdentifyJSON( inJSON: %s )\n", inJSON)
			logger.Debugf("\toutJSON: %s\n", outJSON)
			eng.ShowResults(results)
			logger.Debugf("\n")
		}
		inStr = "abcd@abcd.com"
		maskRule := "EmailMaskRule01"
		if outStr, err := eng.Mask(inStr, maskRule); err == nil {
			logger.Debugf("\t8. Mask( inStr: %s , %s)\n", inStr, maskRule)
			logger.Debugf("\toutStr: %s\n", outStr)
			logger.Debugf("\n")
		}
		// 自定义脱敏，邮箱用户名保留首尾各一个字符，保留所有域名
		if err = eng.RegisterMasker("EmailMaskRule02", func(in string) (string, error) {
			list := strings.Split(in, "@")
			if len(list) >= 2 {
				prefix := list[0]
				domain := list[1]
				if len(prefix) > 2 {
					prefix = "*" + prefix[1:len(prefix)-1] + "*"
				} else if len(prefix) > 0 {
					prefix = "*" + prefix[1:]
				} else {
					return in, fmt.Errorf("%s is not Email", in)
				}
				ret := prefix + "@" + domain
				return ret, nil
			} else {
				return in, fmt.Errorf("%s is not Email", in)
			}
		}); err != nil {
			panic(err)
		}

		inStr = "abcd@abcd.com"
		maskRule = "EmailMaskRule02"
		if outStr, err := eng.Mask(inStr, maskRule); err == nil {
			logger.Debugf("\t9. Mask( inStr: %s , %s)\n", inStr, maskRule)
			logger.Debugf("\toutStr: %s\n", outStr)
			logger.Debugf("\n")
		}

		inStr = "log info:[ uid:10086, phone:18612341234]"
		if outStr, results, err := eng.DeIdentify(inStr); err == nil {
			logger.Debugf("\t10. Detect( inStr: %s )\n", inStr)
			eng.ShowResults(results)
			logger.Debugf("\toutStr: %s\n", outStr)
			logger.Debugf("\n")
		}
		type EmailType string
		// 需要递归的结构体，需要填 `mask:"DEEP"` 才会递归脱敏
		type Foo struct {
			Email         EmailType `mask:"EMAIL"`
			PhoneNumber   string    `mask:"CHINAPHONE"`
			IDCard        string    `mask:"CHINAID"`
			Buffer        string    `mask:"DEIDENTIFY"`
			EmailPtrSlice []*struct {
				Val string `mask:"EMAIL"`
			} `mask:"DEEP"`
			PhoneSlice []string `mask:"CHINAPHONE"`
			ExtInfo    *struct {
				Addr string `mask:"ADDRESS"`
			} `mask:"DEEP"`
			EmailArray [2]string   `mask:"EMAIL"`
			NULLPtr    *Foo        `mask:"DEEP"`
			IFace      interface{} `mask:"ExampleTAG"`
		}
		var inObj = Foo{
			"abcd@abcd.com",
			"18612341234",
			"110225196403026127",
			"我的邮件是abcd@abcd.com",
			[]*struct {
				Val string `mask:"EMAIL"`
			}{{"3333@4444.com"}, {"5555@6666.com"}},
			[]string{"18612341234", ""},
			&struct {
				Addr string "mask:\"ADDRESS\""
			}{"北京市海淀区北三环西路43号"},
			[2]string{"abcd@abcd.com", "3333@4444.com"},
			nil,
			"abcd@abcd.com",
		}
		inPtr := &inObj
		inObj.NULLPtr = inPtr
		inPtrContent, _ := json.Marshal(inPtr)
		inPtrExtInfoContent, _ := json.Marshal(inPtr.ExtInfo)
		logger.Debugf("\t11. MaskStruct( inPtr: %+v, ExtInfo: %+v)\n", string(inPtrContent), string(inPtrExtInfoContent))
		// MaskStruct 参数必须是pointer, 才能修改struct 内部元素
		if outPtr, err := eng.MaskStruct(inPtr); err == nil {
			outPtrContent, _ := json.Marshal(outPtr)
			logger.Debugf("\toutObj: %v, ExtInfo:%+v\n", string(outPtrContent), *inObj.ExtInfo)
			logger.Debugf("\t\t EmailPtrSlice:\n")
			for i, ePtr := range inObj.EmailPtrSlice {
				logger.Debugf("\t\t\t[%d] = %s\n", i, ePtr.Val)
			}
			logger.Debugf("\n")
		} else {
			logger.Debugf("%s\n", err.Error())
		}
		// logger.Debugf("%s\n", eng.GetDefaultConf())
		eng.Close()
	} else {
		logger.Debugf("[dlp] NewEngine error: %s\n", err.Error())
	}
	// output:
	// DLP v1.2.15 Demo:
	//
	//	1. Detect( inStr: 我的邮件是abcd@abcd.com,
	// 18612341234是我的电话
	// 你家住在哪里啊? 我家住在北京市海淀区北三环西路43号,
	// mac地址 06-06-06-aa-bb-cc
	// 收件人：张真人  手机号码：18612341234 )
	//
	//	Total Results: 7
	// [{"rule_id":2,"text":"abcd@abcd.com","mask_text":"a***@********","result_type":"VALUE","key":"","byte_start":15,"byte_end":28,"info_type":"EMAIL","en_name":"EMAIL_address","cn_name":"电子邮箱","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":1,"text":"18612341234","mask_text":"186******34","result_type":"VALUE","key":"","byte_start":30,"byte_end":41,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":8,"text":"我家住在北京市海淀区北三环西路43号","mask_text":"我家住在北京市海淀区北三环西路**号","result_type":"VALUE","key":"","byte_start":80,"byte_end":130,"info_type":"ADDRESS","en_name":"address_cn","cn_name":"中文地址","group_name":"","level":"L1","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":8,"text":"淀区北三环西路43号,","mask_text":"淀区北三环西路**号,","result_type":"VALUE","key":"","byte_start":104,"byte_end":131,"info_type":"ADDRESS","en_name":"address_cn","cn_name":"中文地址","group_name":"","level":"L1","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":10,"text":"06-06-06-aa-bb-cc","mask_text":"06-06-06-**-**-**","result_type":"VALUE","key":"","byte_start":142,"byte_end":159,"info_type":"MACADDR","en_name":"MAC_address","cn_name":"MAC地址","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":9,"text":"张真人","mask_text":"张******","result_type":"VALUE","key":"收件人","byte_start":172,"byte_end":181,"info_type":"NAME","en_name":"name","cn_name":"人名","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":1,"text":"18612341234","mask_text":"186******34","result_type":"VALUE","key":"","byte_start":198,"byte_end":209,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}]
	//	2. DeIdentify( inStr: 我的邮件是abcd@abcd.com,
	// 18612341234是我的电话
	// 你家住在哪里啊? 我家住在北京市海淀区北三环西路43号,
	// mac地址 06-06-06-aa-bb-cc
	// 收件人：张真人  手机号码：18612341234 )
	//	outStr: 我的邮件是a***@********,
	// 186******34是我的电话
	// 你家住在哪里啊? 我家住在北京市海淀区北三环西路**号淀区北三环西路**号,
	// mac地址 06-06-06-**-**-**
	// 收件人：张******  手机号码：186******34
	//
	//	3. Mask( inStr: 18612341234 )
	//	outStr: 186******34
	//
	//	4. DetectMap( inMap: map[k1:my phone is 18612341234 and 18612341234 nothing:nothing uid:10086] )
	//
	//	Total Results: 3
	// [{"rule_id":36,"text":"10086","mask_text":"1****","result_type":"KV","key":"uid","byte_start":0,"byte_end":5,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":1,"text":"18612341234","mask_text":"186******34","result_type":"VALUE","key":"k1","byte_start":12,"byte_end":23,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":1,"text":"18612341234","mask_text":"186******34","result_type":"VALUE","key":"k1","byte_start":28,"byte_end":39,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}]
	//	5. DeIdentifyMap( inMap: map[k1:my phone is 18612341234 and 18612341234 nothing:nothing uid:10086] )
	//	outMap: map[k1:my phone is 186******34 and 186******34 nothing:nothing uid:1****]
	//
	//	Total Results: 3
	// [{"rule_id":36,"text":"10086","mask_text":"1****","result_type":"KV","key":"uid","byte_start":0,"byte_end":5,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":1,"text":"18612341234","mask_text":"186******34","result_type":"VALUE","key":"k1","byte_start":12,"byte_end":23,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":1,"text":"18612341234","mask_text":"186******34","result_type":"VALUE","key":"k1","byte_start":28,"byte_end":39,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}]
	//
	//	6. DetectJSON( inJSON: {"objList":[{"uid":"10086"},{"uid":"[\"aaaa\",\"bbbb\"]"}]} )
	//
	//	Total Results: 3
	// [{"rule_id":36,"text":"aaaa","mask_text":"a***","result_type":"KV","key":"/objlist[1]/uid[0]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"bbbb","mask_text":"b***","result_type":"KV","key":"/objlist[1]/uid[1]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"10086","mask_text":"1****","result_type":"KV","key":"/objlist[0]/uid","byte_start":0,"byte_end":5,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}]
	//	7. DeIdentifyJSONByResult( inJSON: {"objList":[{"uid":"10086"},{"uid":"[\"aaaa\",\"bbbb\"]"}]} , results: [{"rule_id":36,"text":"aaaa","mask_text":"a***","result_type":"KV","key":"/objlist[1]/uid[0]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"bbbb","mask_text":"b***","result_type":"KV","key":"/objlist[1]/uid[1]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"10086","mask_text":"1****","result_type":"KV","key":"/objlist[0]/uid","byte_start":0,"byte_end":5,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}] )
	//	outJSON: {"objList":[{"uid":"1****"},{"uid":"[\"a***\",\"b***\"]"}]}
	//
	//	Total Results: 3
	// [{"rule_id":36,"text":"aaaa","mask_text":"a***","result_type":"KV","key":"/objlist[1]/uid[0]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"bbbb","mask_text":"b***","result_type":"KV","key":"/objlist[1]/uid[1]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"10086","mask_text":"1****","result_type":"KV","key":"/objlist[0]/uid","byte_start":0,"byte_end":5,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}]
	//
	//	7. DeIdentifyJSON( inJSON: {"objList":[{"uid":"10086"},{"uid":"[\"aaaa\",\"bbbb\"]"}]} )
	//	outJSON: {"objList":[{"uid":"1****"},{"uid":"[\"a***\",\"b***\"]"}]}
	//
	//	Total Results: 3
	// [{"rule_id":36,"text":"aaaa","mask_text":"a***","result_type":"KV","key":"/objlist[1]/uid[0]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"bbbb","mask_text":"b***","result_type":"KV","key":"/objlist[1]/uid[1]","byte_start":0,"byte_end":4,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":36,"text":"10086","mask_text":"1****","result_type":"KV","key":"/objlist[0]/uid","byte_start":0,"byte_end":5,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}]
	//
	//	9. Mask( inStr: abcd@abcd.com , EmailMaskRule02)
	//	outStr: *bc*@abcd.com
	//
	//	10. Detect( inStr: log info:[ uid:10086, phone:18612341234] )
	//
	//	Total Results: 3
	// [{"rule_id":36,"text":"10086","mask_text":"1****","result_type":"VALUE","key":"uid","byte_start":15,"byte_end":20,"info_type":"UID","en_name":"userid","cn_name":"用户user_id","group_name":"","level":"L3","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":1,"text":"18612341234","mask_text":"186******34","result_type":"VALUE","key":"","byte_start":28,"byte_end":39,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}},{"rule_id":35,"text":"18612341234","mask_text":"18*******34","result_type":"VALUE","key":"phone","byte_start":28,"byte_end":39,"info_type":"PHONE","en_name":"telephone_number","cn_name":"电话号码","group_name":"","level":"L4","ext_info":{"CnGroup":"用户数据","EnGroup":"user_data"}}]
	//	outStr: log info:[ uid:1****, phone:186******3418*******34]
	//
	//	11. MaskStruct( inPtr: , ExtInfo: {"Addr":"北京市海淀区北三环西路43号"})
	//	outObj: , ExtInfo:{Addr:北京市海淀区北三环西路*****}
	//		 EmailPtrSlice:
	//			[0] = 3***@********
	//			[1] = 5***@********
}

type exampleLogger struct{}

func (e exampleLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (e exampleLogger) Infof(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (e exampleLogger) Warnf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (e exampleLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (e exampleLogger) SetLevel(_ logger.Level) {}
