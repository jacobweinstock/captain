package bmc

type Payload struct {
	Host string `json:"host"`
	Task Task   `json:"task"`
}
type BootDevice struct {
	Device     string `json:"device"`
	Persistent bool   `json:"persistent"`
	EFIBoot    bool   `json:"efiBoot"`
}
type VirtualMedia struct {
	MediaURL string `json:"mediaUrl"`
	Kind     string `json:"kind"`
}
type Task struct {
	Power string `json:"power,omitempty"`
	// Pointers are use so that we can more easily omit the field if it is not set.
	// This matters because the signature payload is generated from the JSON representation of the struct.
	BootDevice   *BootDevice   `json:"bootDevice,omitempty"`
	VirtualMedia *VirtualMedia `json:"virtualMedia,omitempty"`
}
