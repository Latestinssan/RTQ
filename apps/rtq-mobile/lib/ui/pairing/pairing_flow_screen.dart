/// Pairing flow UI.
///
/// Walks the user through scanning a host pairing QR, reviewing the host,
/// entering the local PIN, and confirming. Every meaningful decision is
/// explicit; nothing is silently authorized.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../pairing/pairing_controller.dart';
import '../../protocol/models.dart';
import '../widgets.dart';
import '../widgets/scan_camera.dart';

class PairingFlowScreen extends StatefulWidget {
  const PairingFlowScreen({super.key, required this.controller});

  final PairingController controller;

  @override
  State<PairingFlowScreen> createState() => _PairingFlowScreenState();
}

class _PairingFlowScreenState extends State<PairingFlowScreen> {
  bool _busy = false;

  Future<void> _onPayload(String payload) async {
    if (_busy) return;
    _busy = true;
    try {
      await widget.controller.scan(payload);
    } finally {
      _busy = false;
    }
  }

  Future<void> _pastePayload() async {
    final controller = widget.controller;
    final text = await showDialog<String>(
      context: context,
      builder: (context) => const _PasteDialog(),
    );
    if (text != null && text.isNotEmpty) {
      await controller.scan(text.trim());
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.controller,
      builder: (context, _) {
        final snapshot = widget.controller.snapshot;
        return FlowScaffold(
          title: 'Pair',
          child: switch (snapshot.state) {
            PairingUiState.waiting => _buildWaiting(),
            PairingUiState.scanning => _buildScanning(),
            PairingUiState.pairingReady => _buildPairingReady(snapshot),
            PairingUiState.details => _buildDetails(snapshot),
            PairingUiState.verifying => const _ProgressView(
              label: 'Verifying pairing QR',
            ),
            PairingUiState.signing => const _ProgressView(
              label: 'Signing pairing response',
            ),
            PairingUiState.complete => _buildComplete(snapshot),
            PairingUiState.failed => _buildFailed(snapshot),
          },
        );
      },
    );
  }

  Widget _buildWaiting() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.link,
              size: 88,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(height: 16),
            Text(
              'Pair with an RTQ host',
              style: Theme.of(
                context,
              ).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w800),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              'Scan the pairing QR your host displays. This pins the host’s '
              'public key so future challenge QRs can be verified. The host '
              'never sees your PIN or private key.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 28),
            FilledButton.icon(
              onPressed: widget.controller.beginScanning,
              icon: const Icon(Icons.qr_code_scanner),
              label: const Text('Scan pairing QR'),
            ),
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: _pastePayload,
              icon: const Icon(Icons.content_paste),
              label: const Text('Paste pairing QR text'),
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
        child: const Text(
          'Point the camera at the pairing QR shown by your host.',
          textAlign: TextAlign.center,
        ),
      ),
    );
  }

  Widget _buildPairingReady(PairingSnapshot snapshot) {
    final pairing = snapshot.pairing!;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Icon(
            Icons.verified_outlined,
            size: 64,
            color: Color(0xFF2E7D32),
          ),
          const SizedBox(height: 10),
          Text(
            'Pairing QR verified',
            style: Theme.of(context).textTheme.titleLarge,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 6),
          Text(
            'The QR is signed by the RTQ host shown below.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 16),
          SectionCard(
            title: 'Host',
            icon: Icons.dns_outlined,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                InfoRow('Host ID', pairing.hostId, monospace: true),
                InfoRow('Application', pairing.application),
                if (pairing.userHint != null && pairing.userHint!.isNotEmpty)
                  InfoRow('User hint', pairing.userHint!),
                InfoRow(
                  'Host public key',
                  pairing.hostPublicKey,
                  monospace: true,
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          FilledButton(
            onPressed: widget.controller.showDetails,
            child: const Text('Review & confirm →'),
          ),
          TextButton(
            onPressed: widget.controller.reset,
            child: const Text('Discard'),
          ),
        ],
      ),
    );
  }

  Widget _buildDetails(PairingSnapshot snapshot) {
    final pairing = snapshot.pairing!;
    return _ConfirmPairingView(
      pairing: pairing,
      onConfirm: (pin, deviceName) =>
          widget.controller.complete(pin, deviceName: deviceName),
      onCancel: widget.controller.reset,
    );
  }

  Widget _buildComplete(PairingSnapshot snapshot) {
    final record = snapshot.pairedRecord;
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.check_circle, size: 88, color: Color(0xFF2E7D32)),
            const SizedBox(height: 16),
            Text(
              'Paired',
              style: Theme.of(
                context,
              ).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w800),
            ),
            const SizedBox(height: 10),
            Text(
              'This device now trusts this host. Pairing was recorded on the '
              'host and this device.',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            if (record != null) ...[
              const SizedBox(height: 18),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    children: [
                      InfoRow('Host ID', record.hostId, monospace: true),
                      InfoRow('Application', record.application),
                    ],
                  ),
                ),
              ),
            ],
            const SizedBox(height: 24),
            FilledButton(
              onPressed: widget.controller.reset,
              child: const Text('Done'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFailed(PairingSnapshot snapshot) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.link_off, size: 88, color: Color(0xFFC62828)),
            const SizedBox(height: 16),
            Text(
              'Pairing failed',
              style: Theme.of(
                context,
              ).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w800),
            ),
            const SizedBox(height: 10),
            Text(
              '${snapshot.errorReason ?? 'The host rejected the pairing.'} '
              '\n(${snapshot.errorCode ?? 'pairing.error'})',
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 24),
            FilledButton(
              onPressed: widget.controller.reset,
              child: const Text('Try again'),
            ),
          ],
        ),
      ),
    );
  }
}

class _PasteDialog extends StatefulWidget {
  const _PasteDialog();
  @override
  State<_PasteDialog> createState() => _PasteDialogState();
}

class _PasteDialogState extends State<_PasteDialog> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Paste pairing QR text'),
      content: TextField(
        controller: _controller,
        autofocus: true,
        maxLines: 3,
        decoration: const InputDecoration(
          hintText: 'rtq://pair?v=1&c=…',
          border: OutlineInputBorder(),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(_controller.text),
          child: const Text('Use'),
        ),
      ],
    );
  }
}

class _ConfirmPairingView extends StatefulWidget {
  const _ConfirmPairingView({
    required this.pairing,
    required this.onConfirm,
    required this.onCancel,
  });

  final RtqPairingChallenge pairing;
  final void Function(String pin, String deviceName) onConfirm;
  final VoidCallback onCancel;

  @override
  State<_ConfirmPairingView> createState() => _ConfirmPairingViewState();
}

class _ConfirmPairingViewState extends State<_ConfirmPairingView> {
  final _pinController = TextEditingController();
  final _nameController = TextEditingController(text: 'RTQ device');
  final _formKey = GlobalKey<FormState>();
  bool _submitting = false;

  @override
  void dispose() {
    _pinController.dispose();
    _nameController.dispose();
    super.dispose();
  }

  void _submit() {
    if (_submitting) return;
    if (!_formKey.currentState!.validate()) return;
    setState(() => _submitting = true);
    widget.onConfirm(_pinController.text, _nameController.text.trim());
  }

  @override
  Widget build(BuildContext context) {
    final pairing = widget.pairing;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SectionCard(
            title: 'You are pairing with',
            icon: Icons.dns_outlined,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                InfoRow('Application', pairing.application),
                InfoRow('Host ID', pairing.hostId, monospace: true),
                if (pairing.userHint != null && pairing.userHint!.isNotEmpty)
                  InfoRow('User hint', pairing.userHint!),
              ],
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'Check that this matches the host you expect. Pairing lets this '
            'host ask this device for approvals.',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 14),
          Form(
            key: _formKey,
            child: Column(
              children: [
                TextFormField(
                  controller: _nameController,
                  maxLength: 40,
                  decoration: const InputDecoration(
                    labelText: 'Device name (shown to host)',
                    border: OutlineInputBorder(),
                  ),
                ),
                const SizedBox(height: 10),
                TextFormField(
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
                    labelText: 'Local PIN',
                    border: OutlineInputBorder(),
                    counterText: '',
                  ),
                  onFieldSubmitted: (_) => _submit(),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            style: FilledButton.styleFrom(
              minimumSize: const Size.fromHeight(50),
            ),
            onPressed: _submitting ? null : _submit,
            icon: const Icon(Icons.handshake_outlined),
            label: const Text('Confirm & pair'),
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

class _ProgressView extends StatelessWidget {
  const _ProgressView({required this.label});
  final String label;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 20),
          Text(label, style: Theme.of(context).textTheme.titleMedium),
        ],
      ),
    );
  }
}
