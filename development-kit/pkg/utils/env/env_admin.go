package env

import (
	"fmt"
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/admin"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"strconv"
	"strings"
)

type IEnv interface {
	ToString() string
	ToBool() bool
	ToInt() int
}

type Env struct {
	value interface{}
}

func GetEnvFromAdminOrDefault(databaseRead SQL.InterfaceRead, env, defaultValue string) IEnv {
	entity := &admin.HorusecAdminConfig{}
	response := databaseRead.Find(entity, databaseRead.GetConnection(), entity.GetTable())
	if err := response.GetError(); err != nil {
		logger.LogError(fmt.Sprintf("Error on get env (%s) on database", env), err)
		return &Env{value: GetEnvOrDefault(env, defaultValue)}
	}
	if data := response.GetData(); data == nil {
		return &Env{value: GetEnvOrDefault(env, defaultValue)}
	}
	if value := response.GetData().(*admin.HorusecAdminConfig).ToMap()[strings.ToLower(env)]; value != "" {
		return &Env{value: value}
	}
	return &Env{value: GetEnvOrDefault(env, defaultValue)}
}

func (e *Env) ToString() string {
	return fmt.Sprintf("%v", e.value)
}
func (e *Env) ToBool() bool {
	stringValue := e.ToString()
	return strings.EqualFold(stringValue, "true") || stringValue == "1"
}
func (e *Env) ToInt() int {
	stringValue := e.ToString()
	intValue, err := strconv.Atoi(stringValue)
	logger.LogError(fmt.Sprintf("Error on convert \"%s\" to int", stringValue), err)
	return intValue
}
