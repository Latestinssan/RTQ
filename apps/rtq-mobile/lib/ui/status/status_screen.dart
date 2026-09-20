/// Device status: identity, pairing, and sensitive local management actions.
///
/// Management actions are explicit and destructive actions require
/// confirmation. The public key fingerprint (deviceId) is shown without
/// unlocking — it is public; the seed stays encrypted.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../pairing/pairing_store.dart';
import '../../security/device_key_vault.dart';
import '../widgets.dart';

class StatusScreen extends StatefulWidget {
  const StatusScreen({
    super.key,
    required this.vault,
    required this.pairingStore,
    this.onReset,
  });

  final DeviceKeyVault vault;
  final PairingStore pairingStore;
  final VoidCallback? onReset;

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  bool _initialized = false;
  String? _deviceId;
  PairedHostRecord? _paired;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final initialized = await widget.vault.isInitialized();
    final deviceId = initialized ? await widget.vault.pendingDeviceId() : null;
    final paired = await widget.pairingStore.read();
    if (!mounted) return;
    setState(() {
      _initialized = initialized;
      _deviceId = deviceId;
      _paired = paired;
    });
  }

  Future<void> _changePin() async {
    if (!_initialized) return;
    final result = await showDialog<_PinPair>(
      context: context,
      builder: (context) => const _ChangePinDialog(),
    );
    if (result == null || !mounted) return;
    try {
      await widget.vault.changePin(result.oldPin, result.newPin);
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('PIN changed.')));
    } on WrongPinException {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Current PIN was wrong.')));
    } on ArgumentError catch (error) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text(error.message.toString())));
    }
  }

  Future<void> _unpair() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Unpair host?'),
        content: const Text(
          'This device will no longer trust this host, and the host should no '
          'longer route approvals to this device. This does not delete the '
          'device key.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Keep paired'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: const Color(0xFFC62828),
            ),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Unpair'),
          ),
        ],
      ),
    );
    if (confirm != true || !mounted) return;
    await widget.pairingStore.clear();
    await _refresh();
  }

  Future<void> _wipe() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete device identity?'),
        content: const Text(
          'This permanently deletes this device’s signing key and un-pairs it. '
          'Any host that trusted this device will no longer accept its '
          'approvals. This cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: const Color(0xFFC62828),
            ),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Delete everything'),
          ),
        ],
      ),
    );
    if (confirm != true || !mounted) return;
    await widget.vault.wipe();
    await widget.pairingStore.clear();
    await _refresh();
  }

  @override
  Widget build(BuildContext context) {
    return FlowScaffold(
      title: 'Status',
      child: RefreshIndicator(
        onRefresh: _refresh,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            SectionCard(
              title: 'Device identity',
              icon: Icons.badge_outlined,
              child: _initialized
                  ? Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        InfoRow('Device ID', _deviceId ?? '-', monospace: true),
                        const SizedBox(height: 8),
                        Text(
                          'The private key is stored encrypted on this device '
                          'and is unlocked only with your PIN (plus optional '
                          'biometrics).',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    )
                  : Text(
                      'No device key yet. Create one to approve and pair.',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
            ),
            SectionCard(
              title: 'Paired host',
              icon: Icons.dns_outlined,
              child: _paired == null
                  ? const Text('Not paired with any host.')
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        InfoRow('Host ID', _paired!.hostId, monospace: true),
                        InfoRow('Application', _paired!.application),
                      ],
                    ),
            ),
            const SizedBox(height: 12),
            if (_initialized) ...[
              OutlinedButton.icon(
                onPressed: _changePin,
                icon: const Icon(Icons.password),
                label: const Text('Change PIN'),
              ),
              const SizedBox(height: 8),
            ],
            if (_paired != null) ...[
              OutlinedButton.icon(
                onPressed: _unpair,
                icon: const Icon(Icons.link_off),
                label: const Text('Unpair host'),
              ),
              const SizedBox(height: 8),
            ],
            if (_initialized)
              OutlinedButton.icon(
                style: OutlinedButton.styleFrom(
                  foregroundColor: const Color(0xFFC62828),
                  side: const BorderSide(color: Color(0xFFC62828)),
                ),
                onPressed: _wipe,
                icon: const Icon(Icons.delete_forever_outlined),
                label: const Text('Delete device identity & un-pair'),
              ),
          ],
        ),
      ),
    );
  }
}

class _PinPair {
  const _PinPair(this.oldPin, this.newPin);
  final String oldPin;
  final String newPin;
}

class _ChangePinDialog extends StatefulWidget {
  const _ChangePinDialog();
  @override
  State<_ChangePinDialog> createState() => _ChangePinDialogState();
}

class _ChangePinDialogState extends State<_ChangePinDialog> {
  final _oldController = TextEditingController();
  final _newController = TextEditingController();
  final _formKey = GlobalKey<FormState>();

  @override
  void dispose() {
    _oldController.dispose();
    _newController.dispose();
    super.dispose();
  }

  void _submit() {
    if (!_formKey.currentState!.validate()) return;
    Navigator.of(
      context,
    ).pop(_PinPair(_oldController.text, _newController.text));
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Change PIN'),
      content: Form(
        key: _formKey,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextFormField(
              controller: _oldController,
              obscureText: true,
              keyboardType: TextInputType.number,
              maxLength: 64,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              validator: (value) => (value == null || value.length < 6)
                  ? 'Enter your current PIN.'
                  : null,
              decoration: const InputDecoration(
                labelText: 'Current PIN',
                border: OutlineInputBorder(),
                counterText: '',
              ),
            ),
            const SizedBox(height: 10),
            TextFormField(
              controller: _newController,
              obscureText: true,
              keyboardType: TextInputType.number,
              maxLength: 64,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              validator: (value) => value == null
                  ? 'Enter a new PIN.'
                  : PinPolicy.validate(value),
              decoration: const InputDecoration(
                labelText: 'New PIN',
                border: OutlineInputBorder(),
                counterText: '',
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(onPressed: _submit, child: const Text('Change PIN')),
      ],
    );
  }
}
