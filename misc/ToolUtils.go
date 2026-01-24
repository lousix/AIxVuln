package misc

import (
	"fmt"
	"math"
	"strconv"
)

func GetIntParam(v interface{}) (int, error) {
	if v == nil {
		return 0, fmt.Errorf("parameter not int")
	}

	switch val := v.(type) {
	case int:
		return val, nil
	case int8:
		return int(val), nil
	case int16:
		return int(val), nil
	case int32:
		return int(val), nil
	case int64:
		if val > math.MaxInt || val < math.MinInt {
			return 0, fmt.Errorf("parameter not int") // 溢出检查
		}
		return int(val), nil
	case uint:
		if val > math.MaxInt {
			return 0, fmt.Errorf("parameter not int")
		}
		return int(val), nil
	case uint8:
		return int(val), nil
	case uint16:
		return int(val), nil
	case uint32:
		return int(val), nil
	case uint64:
		return int(val), nil
	case float32:
		// 浮点数转整数，四舍五入
		if val > float32(math.MaxInt) || val < float32(math.MinInt) {
			return 0, fmt.Errorf("parameter not int")
		}
		return int(math.Round(float64(val))), nil
	case float64:
		// 浮点数转整数，四舍五入
		if val > float64(math.MaxInt) || val < float64(math.MinInt) {
			return 0, fmt.Errorf("parameter not int")
		}
		return int(math.Round(val)), nil
	case bool:
		if val {
			return 1, nil
		}
		return 0, nil
	case string:
		// 尝试解析字符串为整数
		if num, err := strconv.ParseInt(val, 10, 64); err == nil {
			if num > math.MaxInt || num < math.MinInt {
				return 0, fmt.Errorf("parameter not int")
			}
			return int(num), nil
		}
		// 如果整数解析失败，尝试解析为浮点数
		if num, err := strconv.ParseFloat(val, 64); err == nil {
			if num > float64(math.MaxInt) || num < float64(math.MinInt) {
				return 0, fmt.Errorf("parameter not int")
			}
			return int(math.Round(num)), nil
		}
		return 0, fmt.Errorf("parameter not int")
	default:
		return 0, fmt.Errorf("parameter not int")
	}
}
