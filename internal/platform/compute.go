package platform

import "context"

// InstanceDisk is a data disk attached when an instance is created.
type InstanceDisk struct {
	// SizeGB is the size in GiB.
	SizeGB int32
	// Device is the device name the platform attaches it as ("/dev/sdb").
	Device string
	// Type is the platform's volume type ("gp3").
	Type string
	// IOPS and Throughput (MiB/s) are sent only to volume types that take
	// them; zero leaves them out.
	IOPS, Throughput int32
	// DeleteOnTermination removes the disk with the instance; data disks
	// are kept by default.
	DeleteOnTermination bool
}

// CreateSpec describes a compute instance to create.
type CreateSpec struct {
	Name   string
	Region string
	Type   string
	// Image is the machine image id; Arch its architecture.
	Image string
	Arch  string
	// Subnet and SecurityGroups place the primary network interface.
	Subnet         string
	SecurityGroups []string
	// KeyPair is the SSH key pair to bind ("" binds none).
	KeyPair  string
	PublicIP bool
	Disk     *InstanceDisk
	// Tags are set on the instance and its volumes, Name included.
	Tags map[string]string
	// ClientToken makes a retried create of the same command idempotent.
	ClientToken string
}

// ResizeSpec is the new size of an instance.
type ResizeSpec struct {
	// Type is the new instance type.
	Type string
}

// ComputeService is the write side of compute instances that platforms
// implement. Each method is one platform call: waits, confirmations and
// the order of the steps (stop, resize, start) belong to the command.
type ComputeService interface {
	// CreateInstance creates an instance and returns its id.
	CreateInstance(ctx context.Context, spec CreateSpec) (id string, err error)
	// DeleteInstance deletes (terminates) an instance.
	DeleteInstance(ctx context.Context, region, id string) error
	// RebootInstance restarts a running instance.
	RebootInstance(ctx context.Context, region, id string) error
	// ResizeInstance changes the type of a stopped instance.
	ResizeInstance(ctx context.Context, region, id string, spec ResizeSpec) error
}
