package clients

// Page contains page metadata that helps navigation.
type Page struct {
	Total        uint64
	Offset       uint64   `json:"offset,omitempty"`
	Limit        uint64   `json:"limit,omitempty"`
	Name         string   `json:"name,omitempty"`
	Order        string   `json:"order,omitempty"`
	Dir          string   `json:"dir,omitempty"`
	Metadata     Metadata `json:"metadata,omitempty"`
	Disconnected bool     // Used for connected or disconnected lists
	Owner        string
	Tag          string
	SharedBy     string
	Status       Status
	Action       string
	Subject      string
	IDs          []string
	Identity     string
}
