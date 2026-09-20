/// Shared QR scanner view.
///
/// A thin wrapper around `mobile_scanner` that reports decoded payload strings
/// (debounced per value). The caller decides what the payload means — this view
/// never interprets or trusts a QR.
library;

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// Best-effort text extraction from a scanned barcode.
String? barcodeText(Barcode barcode) {
  final raw = barcode.rawValue;
  if (raw != null && raw.isNotEmpty) return raw;
  final bytes = barcode.rawBytes;
  if (bytes != null && bytes.isNotEmpty) {
    try {
      final text = utf8.decode(bytes);
      if (text.isNotEmpty) return text;
    } catch (_) {
      return null;
    }
  }
  return null;
}

class ScanCamera extends StatefulWidget {
  const ScanCamera({super.key, required this.onPayload, this.bottomBar});

  final ValueChanged<String> onPayload;
  final Widget? bottomBar;

  @override
  State<ScanCamera> createState() => _ScanCameraState();
}

class _ScanCameraState extends State<ScanCamera> {
  final MobileScannerController _controller = MobileScannerController();
  String? _lastPayload;
  DateTime _lastAt = DateTime.fromMillisecondsSinceEpoch(0);

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _handle(BarcodeCapture capture) {
    final barcode = capture.barcodes.firstOrNull;
    final text = barcode == null ? null : barcodeText(barcode);
    if (text == null || text.isEmpty) return;
    final now = DateTime.now();
    if (text == _lastPayload &&
        now.difference(_lastAt) < const Duration(seconds: 1)) {
      return;
    }
    _lastPayload = text;
    _lastAt = now;
    widget.onPayload(text);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Expanded(
          child: MobileScanner(
            controller: _controller,
            onDetect: _handle,
            errorBuilder: (context, error, child) => Center(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Text('Camera error: $error'),
              ),
            ),
          ),
        ),
        widget.bottomBar ?? const SizedBox.shrink(),
      ],
    );
  }
}
