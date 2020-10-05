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

func (r *Repository) GetVulnByTime(repositoryID uuid.UUID) (vulnManagement []dto.VulnManagement, err error) {
	query := r.databaseRead.
		GetConnection().
		Select("").
		Table("analysis").
		Joins("JOIN vulnerabilities ON analysis.analysis_id = vulnerabilities.analysis_id").
		Where("repository_id = ?", repositoryID)

	return vulnManagement, nil
}
