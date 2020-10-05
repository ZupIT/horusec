package management

type IController interface {
}

type Controller struct {
}

func NewManagementController() IController {
	return &Controller{}
}

func (c *Controller) GetAllVulnerabilities() {

}
