/// The full approval flow UI.
///
/// Renders one dedicated view per [ApprovalUiState] — every state required by
/// the product spec has a visible screen; nothing is collapsed or hidden. The
/// view layer is deliberately thin: all validation, signing and transport is
/// driven by [ApprovalController].
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../approval/approval_controller.dart';
import '../../approval/approval_state.dart';
import '../widgets.dart';
import '../widgets/scan_camera.dart';

String formatEpochMillis(int millis) {
  final dt = DateTime.fromMillisecondsSinceEpoch(millis, isUtc: true).toLocal();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${dt.year}-${two(dt.month)}-${two(dt.day)} '
      '${two(dt.hour)}:${two(dt.minute)}:${two(dt.second)}';
}

class ApprovalFlowScreen extends StatefulWidget {
  const ApprovalFlowScreen({
    super.key,
    required this.controller,
    this.onOpenPairing,
  });

  final ApprovalController controller;
  final VoidCallback? onOpenPairing;

  @override
  State<ApprovalFlowScreen> createState() => _ApprovalFlowScreenState();
}

class _ApprovalFlowScreenState extends State<ApprovalFlowScreen> {
  bool _busy = false;

  void _startScanning() {
    setState(() {
      _busy = false;
    });
    widget.controller.beginScanning();
  }

  Future<void> _onPayload(String payload) async {
    if (_busy) return;
    _busy = true;
    try {
      await widget.controller.scan(payload);
    } finally {
      _busy = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.controller,
      builder: (context, _) {
        final snapshot = widget.controller.snapshot;
        return FlowScaffold(
          title: 'Approve',
          child: switch (snapshot.uiState) {
            ApprovalUiState.waiting => _buildWaiting(),
            ApprovalUiState.scanning => _buildScanning(),
            ApprovalUiState.challengeFound => _buildChallengeFound(snapshot),
            ApprovalUiState.approvalDetails => _buildApprovalDetails(snapshot),
            ApprovalUiState.authenticationRequired => _buildAuthentication(
              snapshot,
            ),
            ApprovalUiState.verifying => _buildProgress('Verifying locally'),
            ApprovalUiState.signing => _buildProgress(
              'Signing with device key',
            ),
            ApprovalUiState.approved => _buildApproved(snapshot),
            ApprovalUiState.denied => _buildDenied(snapshot),
            ApprovalUiState.expired => _buildExpired(snapshot),
            ApprovalUiState.invalidChallenge => _buildInvalidChallenge(
              snapshot,
            ),
            ApprovalUiState.deviceNotPaired => _buildDeviceNotPaired(),
            ApprovalUiState.connectionError => _buildConnectionError(snapshot),
            ApprovalUiState.verificationError => _buildVerificationError(
              snapshot,
            ),
          },
        );
      },
    );
  }

  // -------------------------------------------------------------------------
  // Camera states
  // -------------------------------------------------------------------------

  Widget _buildWaiting() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.qr_code_scanner,
              size: 96,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 20),
            Text(
              'Waiting to scan',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            Text(
              'Point the camera at an RTQ approval QR. '
              'The app never sends your PIN or device key anywhere.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 28),
            FilledButton.icon(
              onPressed: _startScanning,
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Scan a challenge'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildScanning() {
    return ScanCamera(
      onPayload: (text) => _onPayload(text),
      bottomBar: Container(
        width: double.infinity,
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        padding: const EdgeInsets.all(14),
        child: _busy
            ? const Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                  SizedBox(width: 12),
                  Text('Verifying challenge…'),
                ],
              )
            : const Text(
                'Point the camera at the host’s QR. '
                'Any non-RTQ code will be rejected.',
                textAlign: TextAlign.center,
              ),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Detected / review states
  // -------------------------------------------------------------------------

  Widget _buildChallengeFound(ApprovalSnapshot snapshot) {
    final challenge = snapshot.challenge!;
    return _scrollable([
      const Icon(Icons.verified_outlined, size: 64, color: Color(0xFF2E7D32)),
      const SizedBox(height: 12),
      Text(
        'Challenge found & verified',
        style: Theme.of(context).textTheme.titleLarge,
        textAlign: TextAlign.center,
      ),
      const SizedBox(height: 6),
      Text(
        'Host signature verified against your paired host. '
        'Check the operation before approving.',
        textAlign: TextAlign.center,
        style: Theme.of(context).textTheme.bodyMedium,
      ),
      const SizedBox(height: 16),
      SectionCard(
        title: 'Operation',
        icon: Icons.touch_app_outlined,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                RiskBadge(challenge.risk),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    challenge.capability,
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
              ],
            ),
            InfoRow('Origin', challenge.origin),
            InfoRow('Application', challenge.application),
          ],
        ),
      ),
      const SizedBox(height: 12),
      FilledButton(
        onPressed: widget.controller.showApprovalDetails,
        child: const Text('Review approval →'),
      ),
      TextButton(
        onPressed: widget.controller.reset,
        child: const Text('Discard'),
      ),
    ]);
  }

  Widget _buildApprovalDetails(ApprovalSnapshot snapshot) {
    final challenge = snapshot.challenge!;
    final warnings = <Widget>[];
    final summary = challenge.summary;
    if (summary['destructive'] == true ||
        summary['irreversible'] == true ||
        challenge.risk == 'critical' ||
        challenge.risk == 'high') {
      final destructive =
          summary['destructive'] == true || summary['irreversible'] == true;
      warnings.add(
        Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: WarningBanner(
            severity: destructive
                ? WarningSeverity.destructive
                : WarningSeverity.caution,
            message: destructive
                ? 'This operation is destructive or irreversible. '
                      'It cannot be undone.'
                : 'This is a ${challenge.risk}-risk operation. '
                      'Make sure you trust it.',
          ),
        ),
      );
    }

    return _scrollable([
      Row(
        children: [
          RiskBadge(challenge.risk),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              challenge.capability,
              style: Theme.of(
                context,
              ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w800),
            ),
          ),
        ],
      ),
      const SizedBox(height: 10),
      ...warnings,
      SectionCard(
        title: 'What will happen',
        icon: Icons.play_circle_outline,
        child: SummaryList(summary: challenge.summary),
      ),
      SectionCard(
        title: 'Targeted at',
        icon: Icons.ads_click_outlined,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            InfoRow('Origin', challenge.origin),
            InfoRow('Application', challenge.application),
            InfoRow('Host ID', challenge.hostId, monospace: true),
            InfoRow('Capability version', '${challenge.capabilityVersion}'),
          ],
        ),
      ),
      SectionCard(
        title: 'Validity',
        icon: Icons.timer_outlined,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            InfoRow(
              'Expires',
              '${formatEpochMillis(challenge.expiresAt)} '
                  '(${_remainingSeconds(challenge.expiresAt)}s left)',
            ),
            InfoRow('Policy', challenge.policyVersion),
            InfoRow('Challenge ID', challenge.challengeId, monospace: true),
          ],
        ),
      ),
      SectionCard(
        title: 'Integrity bindings',
        icon: Icons.fingerprint,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            InfoRow('Input hash', challenge.inputHash, monospace: true),
            InfoRow('Nonce', challenge.nonce, monospace: true),
            InfoRow(
              'Host public key',
              challenge.hostPublicKey,
              monospace: true,
            ),
          ],
        ),
      ),
      const SizedBox(height: 20),
      FilledButton.icon(
        style: FilledButton.styleFrom(
          backgroundColor: const Color(0xFFC62828),
          minimumSize: const Size.fromHeight(52),
        ),
        onPressed: widget.controller.requestApprovalAuthentication,
        icon: const Icon(Icons.lock_outline),
        label: const Text('Approve'),
      ),
      const SizedBox(height: 8),
      OutlinedButton(
        style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(48)),
        onPressed: widget.controller.requestDenialAuthentication,
        child: const Text('Deny'),
      ),
      TextButton(
        onPressed: widget.controller.reset,
        child: const Text('Discard'),
      ),
    ]);
  }

  int _remainingSeconds(int expiresAt) {
    final diff = expiresAt - DateTime.now().millisecondsSinceEpoch;
    return diff > 0 ? diff ~/ 1000 : 0;
  }

  // -------------------------------------------------------------------------
  // Authentication / progress
  // -------------------------------------------------------------------------

  Widget _buildAuthentication(ApprovalSnapshot snapshot) {
    final challenge = snapshot.challenge;
    final deciding = widget.controller.pendingDecision == 'denied';
    return _PinEntryView(
      requireBiometric: widget.controller.requireBiometric,
      deciding: deciding,
      challengeSummary: challenge == null
          ? ''
          : '${challenge.capability} · ${challenge.risk} risk',
      onSubmit: widget.controller.submitWithPin,
      onCancel: widget.controller.reset,
    );
  }

  Widget _buildProgress(String label) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 20),
          Text(label, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(
            'The device key is unlocked only for this signing; '
            'your PIN is never sent to the host.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodySmall,
          ),
        ],
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Terminal states
  // -------------------------------------------------------------------------

  Widget _buildApproved(ApprovalSnapshot snapshot) {
    return _resultView(
      icon: Icons.check_circle,
      color: const Color(0xFF2E7D32),
      title: 'Approved',
      message:
          'Your approval was signed on this device and accepted by the host.',
      details: [
        ('Challenge ID', snapshot.challengeId ?? '', monospace: true),
        ('Device ID', snapshot.deviceId ?? '', monospace: true),
        (
          'Signed at',
          snapshot.signedAt == null
              ? ''
              : formatEpochMillis(snapshot.signedAt!),
          monospace: false,
        ),
      ],
      action: FilledButton(
        onPressed: widget.controller.reset,
        child: const Text('Done'),
      ),
    );
  }

  Widget _buildDenied(ApprovalSnapshot snapshot) {
    return _resultView(
      icon: Icons.cancel,
      color: const Color(0xFFC62828),
      title: 'Denied',
      message:
          'You denied this approval. The host was told about your decision.',
      details: [
        ('Challenge ID', snapshot.challengeId ?? '', monospace: true),
        (
          'Signed at',
          snapshot.signedAt == null
              ? ''
              : formatEpochMillis(snapshot.signedAt!),
          monospace: false,
        ),
      ],
      action: FilledButton(
        onPressed: widget.controller.reset,
        child: const Text('Done'),
      ),
    );
  }

  Widget _buildExpired(ApprovalSnapshot snapshot) {
    return _resultView(
      icon: Icons.timer_off,
      color: const Color(0xFFF9A825),
      title: 'Expired',
      message: snapshot.errorReason ?? 'This challenge is no longer valid.',
      action: FilledButton(
        onPressed: widget.controller.reset,
        child: const Text('Scan again'),
      ),
    );
  }

  Widget _buildInvalidChallenge(ApprovalSnapshot snapshot) {
    return _resultView(
      icon: Icons.error_outline,
      color: const Color(0xFFEF6C00),
      title: 'Invalid challenge',
      message:
          '${snapshot.errorReason ?? 'This QR is not a valid RTQ challenge.'} '
          '\n(${snapshot.errorCode ?? 'protocol.error'})',
      action: FilledButton(
        onPressed: widget.controller.reset,
        child: const Text('Scan again'),
      ),
    );
  }

  Widget _buildDeviceNotPaired() {
    return _resultView(
      icon: Icons.link_off,
      color: const Color(0xFF546E7A),
      title: 'Device not paired',
      message:
          'This device has no paired RTQ host, so no challenge QR can be '
          'trusted yet. Pair with your host first.',
      action: FilledButton(
        onPressed: widget.onOpenPairing,
        child: const Text('Go to pairing'),
      ),
      secondary: TextButton(
        onPressed: widget.controller.reset,
        child: const Text('Cancel'),
      ),
    );
  }

  Widget _buildConnectionError(ApprovalSnapshot snapshot) {
    return _resultView(
      icon: Icons.cloud_off,
      color: const Color(0xFF546E7A),
      title: 'Connection error',
      message:
          snapshot.errorReason ??
          'The host could not be reached. Nothing was approved.',
      action: FilledButton(
        onPressed: widget.controller.reset,
        child: const Text('Done'),
      ),
    );
  }

  Widget _buildVerificationError(ApprovalSnapshot snapshot) {
    return _resultView(
      icon: Icons.gpp_bad_outlined,
      color: const Color(0xFFC62828),
      title: 'Verification error',
      message:
          '${snapshot.errorReason ?? 'The host rejected this approval.'} '
          '\n(${snapshot.errorCode ?? 'verification.error'})',
      action: FilledButton(
        onPressed: widget.controller.reset,
        child: const Text('Done'),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Shared builders
  // -------------------------------------------------------------------------

  Widget _scrollable(List<Widget> children) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: children,
      ),
    );
  }

  Widget _resultView({
    required IconData icon,
    required Color color,
    required String title,
    required String message,
    List<(String, String, {bool monospace})> details = const [],
    required Widget action,
    Widget? secondary,
  }) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(icon, size: 88, color: color),
            const SizedBox(height: 16),
            Text(
              title,
              style: Theme.of(
                context,
              ).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w800),
            ),
            const SizedBox(height: 10),
            Text(
              message,
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            if (details.isNotEmpty) ...[
              const SizedBox(height: 18),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    children: [
                      for (final detail in details)
                        InfoRow(
                          detail.$1,
                          detail.$2,
                          monospace: detail.monospace,
                        ),
                    ],
                  ),
                ),
              ),
            ],
            const SizedBox(height: 24),
            action,
            if (secondary != null) ...[const SizedBox(height: 8), secondary],
          ],
        ),
      ),
    );
  }
}

/// PIN entry with an explicit decision line (approve / deny).
class _PinEntryView extends StatefulWidget {
  const _PinEntryView({
    required this.requireBiometric,
    required this.deciding,
    required this.challengeSummary,
    required this.onSubmit,
    required this.onCancel,
  });

  final bool requireBiometric;
  final bool deciding;
  final String challengeSummary;
  final void Function(String pin) onSubmit;
  final VoidCallback onCancel;

  @override
  State<_PinEntryView> createState() => _PinEntryViewState();
}

class _PinEntryViewState extends State<_PinEntryView> {
  final _pinController = TextEditingController();
  final _formKey = GlobalKey<FormState>();
  bool _submitting = false;

  @override
  void dispose() {
    _pinController.dispose();
    super.dispose();
  }

  void _submit() {
    if (_submitting) return;
    if (!_formKey.currentState!.validate()) return;
    setState(() => _submitting = true);
    widget.onSubmit(_pinController.text);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final heading = widget.deciding ? 'Confirm denial' : 'Approve?';
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Icon(
            widget.deciding ? Icons.block_outlined : Icons.pin_outlined,
            size: 56,
          ),
          const SizedBox(height: 12),
          Text(
            heading,
            style: theme.textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.w800,
            ),
            textAlign: TextAlign.center,
          ),
          if (widget.challengeSummary.isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(
              widget.challengeSummary,
              textAlign: TextAlign.center,
              style: theme.textTheme.bodyMedium,
            ),
          ],
          const SizedBox(height: 8),
          Text(
            'Enter your local PIN to unlock this device’s signing key. '
            'The PIN never leaves this device.',
            textAlign: TextAlign.center,
            style: theme.textTheme.bodySmall,
          ),
          if (widget.requireBiometric) ...[
            const SizedBox(height: 6),
            Text(
              'Biometric verification will also be requested.',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodySmall,
            ),
          ],
          const SizedBox(height: 20),
          Form(
            key: _formKey,
            child: TextFormField(
              controller: _pinController,
              obscureText: true,
              keyboardType: TextInputType.number,
              maxLength: 64,
              autofocus: true,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              validator: (value) {
                if (value == null || value.length < 6) {
                  return 'Enter your PIN (at least 6 digits).';
                }
                return null;
              },
              decoration: const InputDecoration(
                labelText: 'PIN',
                border: OutlineInputBorder(),
                counterText: '',
              ),
              onFieldSubmitted: (_) => _submit(),
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            style: FilledButton.styleFrom(
              minimumSize: const Size.fromHeight(50),
            ),
            onPressed: _submitting ? null : _submit,
            icon: Icon(
              widget.deciding ? Icons.block : Icons.lock_open_outlined,
            ),
            label: Text(
              widget.deciding ? 'Unlock & confirm denial' : 'Unlock & approve',
            ),
          ),
          TextButton(
            onPressed: _submitting ? null : widget.onCancel,
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }
}
