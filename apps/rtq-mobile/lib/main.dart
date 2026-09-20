/// RTQ Mobile Approval app.
///
/// This app is NOT the authorization authority. It scans a host-signed
/// challenge QR, lets the user review exactly what is being approved, verifies
/// the user locally (PIN, optional biometrics), signs the approval with a
/// device-held Ed25519 key, and submits it. The RTQ host independently
/// verifies the signature, challenge binding, device authorization, expiry,
/// nonce, single-use consumption and policy before granting anything.
library;

import 'package:flutter/material.dart';

import 'approval/approval_controller.dart';
import 'pairing/pairing_controller.dart';
import 'pairing/pairing_store.dart';
import 'security/device_key_vault.dart';
import 'security/flutter_secure_store.dart';
import 'security/local_auth_biometric_gate.dart';
import 'security/secure_store.dart';
import 'transport/approval_transport.dart';
import 'ui/approval/approval_flow_screen.dart';
import 'ui/pairing/pairing_flow_screen.dart';
import 'ui/setup/setup_screen.dart';
import 'ui/status/status_screen.dart';

/// Host base URL, overridable with
/// `flutter run --dart-define=RTQ_HOST_URL=http://192.168.1.10:8787`.
const _hostUrl = String.fromEnvironment(
  'RTQ_HOST_URL',
  defaultValue: 'http://127.0.0.1:8787',
);

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(RtqMobileApp());
}

class RtqMobileApp extends StatefulWidget {
  RtqMobileApp({super.key, SecureStore? store})
    : _store = store ?? FlutterSecureStore();

  final SecureStore _store;

  @override
  State<RtqMobileApp> createState() => _RtqMobileAppState();
}

class _RtqMobileAppState extends State<RtqMobileApp> {
  late final DeviceKeyVault _vault;
  late final PairingStore _pairingStore;
  late final ApprovalController _approval;
  late final PairingController _pairing;
  int _tab = 0;
  bool _setupNeeded = true;

  @override
  void initState() {
    super.initState();
    _vault = DeviceKeyVault(store: widget._store);
    _pairingStore = PairingStore(widget._store);
    final transport = HttpApprovalTransport(baseUrl: Uri.parse(_hostUrl));
    final biometricGate = LocalAuthBiometricGate();
    _approval = ApprovalController(
      vault: _vault,
      biometricGate: biometricGate,
      transport: transport,
      pinnedHostPublicKey: _pairingStore.pinnedHostPublicKey,
    );
    _pairing = PairingController(
      vault: _vault,
      transport: transport,
      store: _pairingStore,
    );
    _checkSetup();
  }

  Future<void> _checkSetup() async {
    final initialized = await _vault.isInitialized();
    if (!mounted) return;
    setState(() => _setupNeeded = !initialized);
  }

  @override
  void dispose() {
    _approval.dispose();
    _pairing.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RTQ Mobile Approval',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1B5E20)),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1B5E20),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: _setupNeeded
          ? SetupScreen(
              vault: _vault,
              onComplete: () {
                _approval.reset();
                setState(() => _setupNeeded = false);
              },
            )
          : HomeShell(
              approval: _approval,
              pairing: _pairing,
              vault: _vault,
              pairingStore: _pairingStore,
              tab: _tab,
              onTabChanged: (tab) => setState(() => _tab = tab),
            ),
    );
  }
}

class HomeShell extends StatelessWidget {
  const HomeShell({
    super.key,
    required this.approval,
    required this.pairing,
    required this.vault,
    required this.pairingStore,
    required this.tab,
    required this.onTabChanged,
  });

  final ApprovalController approval;
  final PairingController pairing;
  final DeviceKeyVault vault;
  final PairingStore pairingStore;
  final int tab;
  final ValueChanged<int> onTabChanged;

  void _openPairing(BuildContext context) {
    onTabChanged(1);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: IndexedStack(
        index: tab,
        children: [
          ApprovalFlowScreen(
            controller: approval,
            onOpenPairing: () => _openPairing(context),
          ),
          PairingFlowScreen(controller: pairing),
          StatusScreen(
            vault: vault,
            pairingStore: pairingStore,
            onReset: approval.reset,
          ),
        ],
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: tab,
        onDestinationSelected: onTabChanged,
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.qr_code_scanner),
            label: 'Approve',
          ),
          NavigationDestination(icon: Icon(Icons.link), label: 'Pair'),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            label: 'Status',
          ),
        ],
      ),
    );
  }
}
