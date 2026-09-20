/// First-run setup: create the device identity (Ed25519 key), wrapped by the
/// user's local PIN.
///
/// The PIN is used only to derive a key-encryption key (PBKDF2) that wraps the
/// device seed (AES-256-GCM). Nothing derived from the PIN is ever persisted or
/// transmitted, so there is no stored PIN to steal.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../security/device_key_vault.dart';
import '../widgets.dart';

class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key, required this.vault, this.onComplete});

  final DeviceKeyVault vault;
  final VoidCallback? onComplete;

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _pinController = TextEditingController();
  final _confirmController = TextEditingController();
  final _formKey = GlobalKey<FormState>();
  bool _creating = false;
  String? _error;

  @override
  void dispose() {
    _pinController.dispose();
    _confirmController.dispose();
    super.dispose();
  }

  Future<void> _create() async {
    if (_creating) return;
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _creating = true;
      _error = null;
    });
    try {
      await widget.vault.create(_pinController.text);
      if (!mounted) return;
      widget.onComplete?.call();
    } on ArgumentError catch (error) {
      if (!mounted) return;
      setState(() {
        _creating = false;
        _error = error.message.toString();
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _creating = false;
        _error = 'Could not create the device key.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return FlowScaffold(
      title: 'Set up device key',
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Icon(Icons.key, size: 64),
            const SizedBox(height: 12),
            Text(
              'Create your device identity',
              style: theme.textTheme.titleLarge?.copyWith(
                fontWeight: FontWeight.w800,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              'This device generates a fresh Ed25519 signing key. The key is '
              'encrypted on this device with a key derived from your PIN. '
              'Neither the PIN nor the private key ever leave this device, '
              'even during pairing or approval.',
              textAlign: TextAlign.center,
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 20),
            Form(
              key: _formKey,
              child: Column(
                children: [
                  TextFormField(
                    controller: _pinController,
                    obscureText: true,
                    keyboardType: TextInputType.number,
                    maxLength: 64,
                    autofocus: true,
                    inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                    validator: _validatePin,
                    decoration: const InputDecoration(
                      labelText: 'Choose a PIN (6+ digits)',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 10),
                  TextFormField(
                    controller: _confirmController,
                    obscureText: true,
                    keyboardType: TextInputType.number,
                    maxLength: 64,
                    inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                    validator: (value) {
                      if (value != _pinController.text) {
                        return 'PINs do not match.';
                      }
                      return null;
                    },
                    decoration: const InputDecoration(
                      labelText: 'Confirm PIN',
                      border: OutlineInputBorder(),
                    ),
                    onFieldSubmitted: (_) => _create(),
                  ),
                ],
              ),
            ),
            if (_error != null) ...[
              const SizedBox(height: 12),
              WarningBanner(
                message: _error!,
                severity: WarningSeverity.caution,
              ),
            ],
            const SizedBox(height: 18),
            FilledButton.icon(
              style: FilledButton.styleFrom(
                minimumSize: const Size.fromHeight(50),
              ),
              onPressed: _creating ? null : _create,
              icon: _creating
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.create_outlined),
              label: Text(_creating ? 'Creating…' : 'Create device key'),
            ),
          ],
        ),
      ),
    );
  }

  String? _validatePin(String? value) {
    final error = value == null ? null : PinPolicy.validate(value);
    return error;
  }
}
