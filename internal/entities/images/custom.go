package images

import (
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec/internal/enums/images"
)

type Custom map[string]string

func NewCustomImages() map[string]string {
	customMap := map[string]string{}
	allLanguages := languages.Generic.MapLanguagesEnableInCLI()
	imagesEnableToCustom := images.MapValues()
	for langEnable := range imagesEnableToCustom {
		for lang, key := range allLanguages {
			if langEnable == lang {
				customMap[key] = ""
			}
		}
	}
	return customMap
}
