@kernel-builder @slow @windows @hyperv @network
Feature: Use a kernel produced by kernel-builder
  A Jyth user needs the emitted kernel to run a guest, not merely look like a kernel file.
  The scenarios run serially in file order: the cold build warms the CLI
  custom-kernel cache, so the warm and failure scenarios can rely on it.

  Scenario: A pinned kernel build starts a new Jyth guest
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "6.6.14"
    When the user builds the kernel with its default configuration
    And the user starts a new Alpine guest with the resulting artifact
    Then the guest reports kernel release "6.6.14"

  Scenario: A warm custom-kernel cache serves the built kernel without recompiling
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "6.6.14"
    When the user builds the kernel with its default configuration
    And the user builds the kernel again with its default configuration
    Then the second build reports the kernel was served from cache

  Scenario: The pinned default kernel launches a Jyth guest
    Given a supported Windows Hyper-V host
    When the user starts an Alpine guest with the default kernel
    Then the guest reports kernel release "6.6.13-linuxkit"

  Scenario: A failing guest build publishes no cache record and leaves no live resources
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "6.6.14"
    When the user builds the kernel with a configuration missing a required option
    Then the build fails without publishing a custom kernel cache record
    And no abandoned live-host resources remain

  Scenario: Concurrent identical custom builds compile exactly once
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "7.1.7"
    When two users build the kernel with the same configuration at the same time
    Then both builds succeed and exactly one reports a fresh compilation

  # Runs one additional full kernel compile (~15-20 min) with a complete
  # config that appends CONFIG_LOCALVERSION="-jyth-e2e"; filter it out with
  # `-- --tags "not @config-change"` when only the base gates are needed.
  @config-change
  Scenario: A custom complete configuration forces one new compilation and changes the kernel
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "6.6.14"
    When the user builds the kernel with a complete configuration declaring a local version
    Then the build reports a fresh compilation
    When the user starts a new Alpine guest with the resulting artifact
    Then the guest reports kernel release "6.6.14-jyth-e2e"
    When the user builds the kernel again with the same complete configuration
    Then the second build reports the kernel was served from cache
