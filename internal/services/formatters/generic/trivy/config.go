package trivy

type Cmd string

func (c Cmd) ToString() string {
	return string(c)
}

const CmdFs Cmd = `
		{{WORK_DIR}}
		TRIVY_NEW_JSON_SCHEMA=true trivy fs  -f json -o result.json ./ &> /dev/null
		cat result.json
  `

const CmdConfig Cmd = `
		{{WORK_DIR}}
		TRIVY_NEW_JSON_SCHEMA=true trivy config -f json -o result.json ./ &> /dev/null 
		cat result.json
  `
