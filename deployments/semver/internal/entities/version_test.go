package entities

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestNewVersion(t *testing.T) {
	Convey("Given an invalid version string format", t, func() {
		versionStr := "dumb"
		Convey("When tries to instantiate a new Version", func() {
			Convey("Then should return an error message", func() {
				version, err := NewVersion(versionStr)
				So(version, ShouldBeNil)
				So(err, ShouldBeError)
			})
		})
	})

	Convey("Given an valid version string format", t, func() {
		Convey("When tries to instantiate an alpha version", func() {
			Convey("Should not return an error", func() {
				version, err := NewVersion("1.2.31-alpha.1")
				So(version, ShouldNotBeNil)
				So(err, ShouldBeNil)
			})

			Convey("When tries to instantiate an beta version", func() {
				Convey("Should not return an error", func() {
					version, err := NewVersion("1.2.32-beta.1")
					So(version, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})
			})

			Convey("When tries to instantiate an release candidate version", func() {
				Convey("Should not return an error", func() {
					version, err := NewVersion("1.2.33-rc.1")
					So(version, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})
			})

			Convey("When tries to instantiate an release version", func() {
				Convey("Should not return an error", func() {
					version, err := NewVersion("1.2.34")
					So(version, ShouldNotBeNil)
					So(err, ShouldBeNil)
				})
			})
		})
	})
}
