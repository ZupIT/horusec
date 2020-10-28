package auth

type HorusecRoles string

const (
	ApplicationAdmin     HorusecRoles = "applicationAdmin"
	CompanyMember        HorusecRoles = "companyMember"
	CompanyAdmin         HorusecRoles = "companyAdmin"
	RepositoryMember     HorusecRoles = "repositoryMember"
	RepositorySupervisor HorusecRoles = "repositorySupervisor"
	RepositoryAdmin      HorusecRoles = "repositoryAdmin"
)

func (h HorusecRoles) IsInvalid() bool {
	for _, v := range h.Values() {
		if v == h {
			return false
		}
	}

	return true
}

func (h HorusecRoles) Values() []HorusecRoles {
	return []HorusecRoles{
		ApplicationAdmin,
		CompanyMember,
		CompanyAdmin,
		RepositoryMember,
		RepositorySupervisor,
		RepositoryAdmin,
	}
}

func (h HorusecRoles) IsEqual(value string) bool {
	return value == h.ToString()
}

func (h HorusecRoles) ToString() string {
	return string(h)
}
