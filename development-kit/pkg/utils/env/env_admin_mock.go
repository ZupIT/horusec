package env

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"github.com/jinzhu/gorm"
)

func GlobalAdminReadMock(rowsAffected int, err error, data interface{}) *relational.MockRead {
	conn, _ := gorm.Open("sqlite3", ":memory:")
	mockRead := &relational.MockRead{}
	mockRead.On("GetConnection").Return(conn)
	mockRead.On("Find").Return(response.NewResponse(rowsAffected, err, data))
	return mockRead
}
