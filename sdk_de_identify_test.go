package dlp_test

import (
	"testing"

	dlp "github.com/laojianzi/godlp"
)

func TestEngine_DeIdentify(t *testing.T) {
	eng, err := dlp.NewEngine("replace.your.psm")
	if err != nil {
		t.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		t.Fatal(err)
	}

	inputText := `我的邮件是abcd@abcd.com,
18612341234是我的电话
你家住在哪里啊? 我家住在北京市海淀区北三环西路43号,
mac地址 06-06-06-aa-bb-cc
收件人：张真人  手机号码：18612341234`

	gotOutputText, _, err := eng.DeIdentify(inputText)
	if err != nil {
		t.Fatal(err)
	}

	wantOutputText := `我的邮件是a***@********,
186******34是我的电话
你家住在哪里啊? 我家住在北京市海淀区北三环西路**号,
mac地址 06-06-06-**-**-**
收件人：张******  手机号码：186******34`
	if gotOutputText != wantOutputText {
		t.Errorf("DeIdentify() \ngot = %v, \nwant = %v", gotOutputText, wantOutputText)
	}
}
