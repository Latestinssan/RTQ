/// UI states for the approval flow.
///
/// Every state required by the product spec is represented here and has a
/// dedicated screen in `lib/ui/approval/`; no state collapses into another.
library;

import '../protocol/models.dart' show RtqChallenge;

enum ApprovalUiState {
  waiting('Waiting'),
  scanning('Scanning'),
  challengeFound('Challenge found'),
  verifying('Verifying'),
  approvalDetails('Approval details'),
  authenticationRequired('Authentication required'),
  signing('Signing'),
  approved('Approved'),
  denied('Denied'),
  expired('Expired'),
  invalidChallenge('Invalid challenge'),
  deviceNotPaired('Device not paired'),
  connectionError('Connection error'),
  verificationError('Verification error');

  const ApprovalUiState(this.label);
  final String label;

  bool get isBlockingFailure =>
      this == expired ||
      this == invalidChallenge ||
      this == deviceNotPaired ||
      this == connectionError ||
      this == verificationError;
}

/// Immutable snapshot of the approval flow for widgets.
class ApprovalSnapshot {
  const ApprovalSnapshot({
    required this.uiState,
    this.challenge,
    this.errorCode,
    this.errorReason,
    this.deviceId,
    this.challengeId,
    this.signedAt,
    this.decision,
  });

  final ApprovalUiState uiState;
  final RtqChallenge? challenge;
  final String? errorCode;
  final String? errorReason;
  final String? deviceId;
  final String? challengeId;
  final int? signedAt;
  final String? decision;
}
