@kernel-v2 @slow @windows @hyperv @network
Feature: Jyth review remediation v2 custom-build evidence
  The v2 custom-build contract (impl/JythReviewRemediationPlan.md WP1/WP2)
  gives every compilation a unique ephemeral build disk and a cache identity
  that covers the immutable source pin. These scenarios lock the live-host
  evidence that cannot be proven without HCS.

  Scenario: A cold v2 build leaves no generated build VHDX
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "7.1.7"
    When the user builds the kernel with its default configuration
    Then no generated build VHDX remains on the host

  Scenario: A warm v2 request returns from cache without recompiling
    Given a supported Windows Hyper-V host
    And kernel-builder is configured to build Linux "7.1.7"
    When the user builds the kernel with its default configuration
    And the user builds the kernel again with its default configuration
    Then the second build reports the kernel was served from cache
