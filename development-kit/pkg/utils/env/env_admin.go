package env

import (
	"fmt"
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/admin"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"strconv"
	"strings"
)

type IEnvAdmin interface {
	ToString() string
	ToBool() bool
	ToInt() int
}

type EnvAdmin struct {
	value interface{}
}

func GetEnvFromAdminOrDefault(databaseRead SQL.InterfaceRead, env, defaultValue string) IEnvAdmin {
	entity := &admin.HorusecAdminConfig{}
	response := databaseRead.Find(entity, databaseRead.GetConnection(), entity.GetTable())
	if err := response.GetError(); err != nil {
		logger.LogError(fmt.Sprintf("Error on get env (%s) on database", env), err)
		return &EnvAdmin{value: GetEnvOrDefault(env, defaultValue)}
	}
	if data := response.GetData(); data == nil {
		return &EnvAdmin{value: GetEnvOrDefault(env, defaultValue)}
	}
	if value := response.GetData().(*admin.HorusecAdminConfig).ToMap()[strings.ToLower(env)]; value != "" {
		return &EnvAdmin{value: value}
	}
	return &EnvAdmin{value: GetEnvOrDefault(env, defaultValue)}
}

func (e *EnvAdmin) ToString() string {
	return fmt.Sprintf("%v", e.value)
}
func (e *EnvAdmin) ToBool() bool {
	stringValue := e.ToString()
	return strings.EqualFold(stringValue, "true") || stringValue == "1"
}
func (e *EnvAdmin) ToInt() int {
	stringValue := e.ToString()
	intValue, err := strconv.Atoi(stringValue)
	logger.LogError(fmt.Sprintf("Error on convert \"%s\" to int", stringValue), err)
	return intValue
}
