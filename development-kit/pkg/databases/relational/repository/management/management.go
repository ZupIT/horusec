package management

import (
	SQL "github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
	"github.com/ZupIT/horusec/development-kit/pkg/entities/api/dto"
	"github.com/google/uuid"
)

type IManagementRepository interface {
}

type Repository struct {
	databaseRead  SQL.InterfaceRead
	databaseWrite SQL.InterfaceWrite
}

func NewManagementRepository(databaseRead SQL.InterfaceRead, databaseWrite SQL.InterfaceWrite) IManagementRepository {
	return &Repository{
		databaseRead:  databaseRead,
		databaseWrite: databaseWrite,
	}
}

func (r *Repository) GetVulnByTime(repositoryID uuid.UUID) (managementList []dto.ManagementList, err error) {
	return managementList, nil
}
