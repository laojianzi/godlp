package dlp

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"testing"
)

var (
	CallerSys = "caller.sys"
)

func BenchmarkEngine_NewAndClose(b *testing.B) {
	if eng, err := NewEngine(CallerSys); err == nil {
		for i := 0; i < b.N; i++ {
			eng.Close()
		}
	} else {
		b.Fatal(err)
	}
}

// public func
func BenchmarkEngine_ApplyConfigDefault(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if eng, err := NewEngine(CallerSys); err == nil {
			if err = eng.ApplyConfigDefault(); err != nil {
				b.Fatal(err)
			}
		} else {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngine_DeIdentify1k(b *testing.B) {
	text, err := Read("./testcases/test_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	if err != nil {
		b.Fatal(err)
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = eng.DeIdentify(text); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngine_DeIdentify10k(b *testing.B) {
	src, err := Read("./testcases/test_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	text := dupString(src, 10)
	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	if err != nil {
		b.Fatal(err)
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = eng.DeIdentify(text); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngine_DeIdentify100k(b *testing.B) {
	src, err := Read("./testcases/test_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	text := dupString(src, 100)
	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	if err != nil {
		b.Fatal(err)
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = eng.DeIdentify(text); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngine_DeIdentify1m(b *testing.B) {
	src, err := Read("./testcases/test_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	text := dupString(src, 1000)
	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	if err != nil {
		b.Fatal(err)
		return
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = eng.DeIdentify(text); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEngine_DeIdentifyJSON1k(b *testing.B) {
	text, err := Read("./testcases/test_json_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = eng.DeIdentifyJSON(text)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkEngine_DeIdentifyJSON10k(b *testing.B) {
	src, err := Read("./testcases/test_json_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	text, err := dupJson(src, 10)
	if err != nil {
		b.Fatal(err)
	}

	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = eng.DeIdentifyJSON(text); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkEngine_DeIdentifyJSON100k(b *testing.B) {
	src, err := Read("./testcases/test_json_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	text, err := dupJson(src, 100)
	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err = eng.DeIdentifyJSON(text)
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkEngine_DeIdentifyJSON1m(b *testing.B) {
	src, err := Read("./testcases/test_json_1k.txt")
	if err != nil {
		b.Fatal(err)
	}

	text, err := dupJson(src, 1000)
	if err != nil {
		b.Fatal(err)
	}

	eng, err := NewEngine(CallerSys)
	if err != nil {
		b.Fatal(err)
	}

	if err = eng.ApplyConfigDefault(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err = eng.DeIdentifyJSON(text); err != nil {
			b.Fatal(err)
		}
	}
}

/**
 * 判断文件是否存在  存在返回 true 不存在返回false
 */
func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

// 读取到file中，再利用ioutil将file直接读取到[]byte中, 这是最优
func Read(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fd, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(fd), nil
}

func dupString(src string, coefficient int) string {
	var buffer bytes.Buffer
	for i := 0; i < coefficient; i++ {
		buffer.WriteString(src)
	}
	return buffer.String()
}

func dupJson(src string, coefficient int) (result string, err error) {
	dst := make(map[string]map[string]string)
	item := make(map[string]string)
	err = json.Unmarshal([]byte(src), &item)
	if err != nil {
		return
	}

	for i := 0; i < coefficient; i++ {
		dst[strconv.Itoa(i)] = item
	}
	b, err := json.Marshal(dst)
	if err != nil {
		return
	}
	result = string(b)
	return
}
