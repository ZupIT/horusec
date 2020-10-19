package auth

type HorusRoles string

const (
	CompanyMember        HorusRoles = "companyMember"
	CompanyAdmin         HorusRoles = "companyAdmin"
	RepositoryMember     HorusRoles = "repositoryMember"
	RepositorySupervisor HorusRoles = "repositorySupervisor"
	RepositoryAdmin      HorusRoles = "repositoryAdmin"
)

func (h HorusRoles) IsInvalid() bool {
	for _, v := range h.Values() {
		if v == h {
			return false
		}
	}

	return true
}

func (h HorusRoles) Values() []HorusRoles {
	return []HorusRoles{
		CompanyMember,
		CompanyAdmin,
		RepositoryMember,
		RepositorySupervisor,
		RepositoryAdmin,
	}
}

func (h HorusRoles) IsEqual(value string) bool {
	return value == h.ToString()
}

func (h HorusRoles) ToString() string {
	return string(h)
}
