@kernel-7 @slow @windows @hyperv @network
Feature: Use the latest Linux 7 kernel produced by kernel-builder
  A Jyth user needs the current stable Linux 7 kernel to run a guest, not
  merely look like a kernel file. This scenario pins the latest stable
  Linux 7 release at the time of writing (7.1.7, kernel.org 2026-08-06);
  bump it together with SUPPORTED_KERNEL_VERSIONS when a newer release
  is validated.

  Scenario: A pinned Linux 7 kernel build starts a new Jyth guest
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "7.1.7"
    When the user builds the kernel with its default configuration
    And the user starts a new Alpine guest with the resulting artifact
    Then the guest reports kernel release "7.1.7"
