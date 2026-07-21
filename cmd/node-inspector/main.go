package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	mountPoint := environment("INSPECTION_MOUNT", "/mnt/runtime-check")
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		log.Fatalf("create inspection mount point: %v", err)
	}

	// This is the deliberate compatibility dependency for the POC. mount(2)
	// needs CAP_SYS_ADMIN and is commonly denied by runtime-default seccomp and
	// AppArmor profiles. A future cluster-wide default must therefore be tested
	// in this repository before rollout.
	command := exec.Command("mount", "-t", "tmpfs", "tmpfs", mountPoint)
	if output, err := command.CombinedOutput(); err != nil {
		log.Fatalf("mount runtime inspection filesystem: %v: %s", err, output)
	}
	defer func() {
		_ = exec.Command("umount", mountPoint).Run()
	}()

	http.HandleFunc("/healthz", func(response http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(response, "ok")
	})
	log.Println("node-inspector listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
