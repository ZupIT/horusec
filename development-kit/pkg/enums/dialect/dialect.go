package dialect

type Dialect string

const (
	Postgres Dialect = "postgres"
	SQLite   Dialect = "sqlite"
	Unknown  Dialect = "unknown"
)

func (d Dialect) IsValid() bool {
	for _, v := range d.Values() {
		if v == d {
			return true
		}
	}

	return false
}

func (d Dialect) ToString() string {
	return string(d)
}

func (d Dialect) Values() []Dialect {
	return []Dialect{
		Postgres,
		SQLite,
	}
}
