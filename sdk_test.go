package dlp_test

import (
	"os"
	"runtime"
	"testing"

	"gopkg.in/yaml.v2"

	dlp "github.com/laojianzi/godlp"
	"github.com/laojianzi/godlp/header"
	"github.com/laojianzi/godlp/logger"
)

type RuleTestItem struct {
	RuleID int32  `yaml:"RuleID"`
	In     string `yaml:"In"`
	Out    string `yaml:"Out"`
}

type RuleTest struct {
	Date     string         `yaml:"Date"`
	TestList []RuleTestItem `yaml:"TestList"`
}

// public func
func TestMain(m *testing.M) {
	setup()

	code := m.Run()
	defer os.Exit(code)

	shutdown()
}

func TestRule(t *testing.T) {
	testPath := "./testdata/rule_test.yml"
	buf, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatal(err)
	}

	ruleTestPtr := new(RuleTest)
	if err = yaml.Unmarshal(buf, ruleTestPtr); err != nil {
		t.Fatal(err)
	}

	t.Logf("%s: Data:%s", testPath, ruleTestPtr.Date)
	eng, err := dlp.NewEngine("replace.your.psm")
	if err != nil {
		t.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		t.Fatal(err)
	}

	for _, item := range ruleTestPtr.TestList {
		out, results, err := eng.DeIdentify(item.In)
		if err != nil {
			t.Fatal(err)
		}

		if len(results) == 0 && item.RuleID == 0 { // no sensitive info found, it's ok
			// check ok
			continue
		}
		if out == item.Out && len(results) >= 1 && results[0].RuleID == item.RuleID {
			// check ok
			continue
		}

		resultId := int32(-1)
		if len(results) >= 1 {
			resultId = results[0].RuleID
		}

		t.Errorf("Error RuleId: %d, in: %s, out: %s, DeIdentify: %s, Results RuleId: %d", item.RuleID, item.In, item.Out, out, resultId)
		eng.ShowResults(results)
	}

	t.Logf("Total %d Rule Test Case pass", len(ruleTestPtr.TestList))
}

func TestDeIdentifyJSONByResult(t *testing.T) {
	jsonBody := `
				{
					"name": "abcdefg",
					"uid": "1234567890"
				}
				`
	eng, err := dlp.NewEngine("replace.your.psm")
	if err != nil {
		t.Error(err)
	}

	err = eng.ApplyConfigDefault()
	if err != nil {
		t.Error(err)
	}

	// detectRes contains NAME and UID
	detectRes, err := eng.DetectJSON(jsonBody)
	if err != nil {
		t.Error(err)
	}

	// de identify the original text
	out, err := eng.DeIdentifyJSONByResult(jsonBody, detectRes)
	if err != nil {
		t.Error(err)
	}

	if out != "{\"name\":\"abc****\",\"uid\":\"1*********\"}" {
		t.Error("incorrect output")
	}

	// remove the rule NAME from the detectResults
	for _, r := range detectRes {
		newDetectRes := make([]*header.DetectResult, 0)
		if r.InfoType != "NAME" {
			newDetectRes = append(newDetectRes, r)
		}

		detectRes = newDetectRes
	}

	// apply the new rule on the original text
	out, err = eng.DeIdentifyJSONByResult(jsonBody, detectRes)
	if err != nil {
		t.Error(err)
	}

	// the removed rule should be ignored
	if out != "{\"name\":\"abcdefg\",\"uid\":\"1*********\"}" {
		t.Error("incorrect output")
	}

	// apply the rule UID on a JSON text which doesn't have an UID
	jsonBody = "{\"name\":\"abcdefg\"}"
	out, err = eng.DeIdentifyJSONByResult(jsonBody, detectRes)
	if err != nil {
		t.Error(err)
	}

	if out != jsonBody {
		t.Error("incorrect output")
	}
}

// private func

func setup() {
	runtime.GOMAXPROCS(1)
	logger.SetLevel(logger.LevelError)
}

func shutdown() {}
