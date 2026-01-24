package Web

type Container struct {
	ContainerId string   `json:"containerId"`
	ContainerIP string   `json:"containerIP"`
	Image       string   `json:"image"`
	WebPort     []string `json:"webPort"`
}
