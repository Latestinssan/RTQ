/// Approval-result transport.
///
/// The QR carries the challenge; the *result* travels over this transport. The
/// transport is untrusted — the host verifies the device signature and the
/// challenge binding regardless of what the channel is. There is deliberately no
/// API here for sending a PIN or a private key.
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

class PairingSession {
  const PairingSession({
    required this.payload,
    required this.pairingId,
    required this.expiresAt,
  });

  final String payload;
  final String pairingId;
  final int expiresAt;
}

class TransportResult<T> {
  const TransportResult.ok(this.value) : ok = true, code = null, reason = null;
  const TransportResult.fail(this.code, this.reason) : ok = false, value = null;

  final bool ok;
  final T? value;
  final String? code;
  final String? reason;
}

abstract class ApprovalTransport {
  /// Host creates a pairing challenge for the device to scan.
  Future<TransportResult<PairingSession>> startPairing();

  /// Device submits a signed pairing response.
  Future<TransportResult<String>> completePairing(String responseJson);

  /// Device submits a signed approval.
  Future<TransportResult<String>> submitApproval(String approvalJson);
}

/// HTTP implementation of [ApprovalTransport].
///
/// The base URL is not a trust boundary. A failure to reach the host is a
/// [TransportResult.fail]; it never produces an approval.
class HttpApprovalTransport implements ApprovalTransport {
  HttpApprovalTransport({
    required this.baseUrl,
    http.Client? client,
    this.timeout = const Duration(seconds: 15),
    Map<String, String>? headers,
  }) : _client = client ?? http.Client(),
       _headers = headers ?? const <String, String>{};

  final Uri baseUrl;
  final http.Client _client;
  final Duration timeout;
  final Map<String, String> _headers;

  Uri _endpoint(String path) => baseUrl.resolve(path);

  /// Decodes a JSON body, returning null on malformed JSON.
  Object? _tryDecode(String body) {
    try {
      return jsonDecode(body);
    } on FormatException {
      return null;
    }
  }

  Future<http.Response> _post(String path, {Object? body}) => _client
      .post(
        _endpoint(path),
        headers: <String, String>{
          'content-type': 'application/json',
          ..._headers,
        },
        body: body == null ? null : (body is String ? body : jsonEncode(body)),
      )
      .timeout(timeout);

  @override
  Future<TransportResult<PairingSession>> startPairing() async {
    try {
      final response = await _post('/pair/start');
      if (response.statusCode != 200) {
        return TransportResult.fail(
          'transport.http_${response.statusCode}',
          'Host refused to start pairing',
        );
      }
      final decodedRaw = _tryDecode(response.body);
      if (decodedRaw is! Map) {
        return const TransportResult.fail(
          'transport.malformed_response',
          'Host returned a malformed pairing response',
        );
      }
      final decoded = Map<String, Object?>.from(decodedRaw);
      final payload = decoded['payload'];
      final pairingId = decoded['pairingId'];
      final expiresAt = decoded['expiresAt'];
      if (payload is! String || pairingId is! String || expiresAt is! int) {
        return const TransportResult.fail(
          'transport.malformed_response',
          'Host pairing response is missing fields',
        );
      }
      return TransportResult.ok(
        PairingSession(
          payload: payload,
          pairingId: pairingId,
          expiresAt: expiresAt,
        ),
      );
    } catch (_) {
      return const TransportResult.fail(
        'transport.connection_error',
        'Could not reach the host',
      );
    }
  }

  @override
  Future<TransportResult<String>> completePairing(String responseJson) async {
    return _submit('/pair/complete', responseJson, idField: 'deviceId');
  }

  @override
  Future<TransportResult<String>> submitApproval(String approvalJson) async {
    return _submit('/approve', approvalJson, idField: 'challengeId');
  }

  Future<TransportResult<String>> _submit(
    String path,
    String body, {
    required String idField,
  }) async {
    try {
      final response = await _post(path, body: body);
      Map<String, Object?>? decoded;
      try {
        final raw = jsonDecode(response.body);
        if (raw is Map) decoded = Map<String, Object?>.from(raw);
      } catch (_) {
        decoded = null;
      }
      if (response.statusCode == 200 && decoded?['ok'] == true) {
        final id = decoded?[idField];
        return TransportResult.ok(id is String ? id : '');
      }
      return TransportResult.fail(
        (decoded?['code'] as String?) ??
            'transport.http_${response.statusCode}',
        (decoded?['reason'] as String?) ?? 'Host rejected the submission',
      );
    } on TimeoutException {
      return const TransportResult.fail(
        'transport.timeout',
        'The host did not respond in time',
      );
    } catch (_) {
      return const TransportResult.fail(
        'transport.connection_error',
        'Could not reach the host',
      );
    }
  }
}

/// In-memory transport for tests and the offline demo.
class FakeApprovalTransport implements ApprovalTransport {
  FakeApprovalTransport({
    this.pairingSession,
    this.submitResult = const TransportResult.ok(''),
    this.completeResult = const TransportResult.ok('device-1'),
  });

  PairingSession? pairingSession;
  TransportResult<String> submitResult;
  TransportResult<String> completeResult;
  int startCalls = 0;
  int completeCalls = 0;
  int submitCalls = 0;
  final List<String> submittedApprovals = <String>[];
  final List<String> completedResponses = <String>[];

  @override
  Future<TransportResult<PairingSession>> startPairing() async {
    startCalls++;
    final session = pairingSession;
    if (session == null) {
      return const TransportResult.fail(
        'transport.unavailable',
        'No pairing session configured',
      );
    }
    return TransportResult.ok(session);
  }

  @override
  Future<TransportResult<String>> completePairing(String responseJson) async {
    completeCalls++;
    completedResponses.add(responseJson);
    return completeResult;
  }

  @override
  Future<TransportResult<String>> submitApproval(String approvalJson) async {
    submitCalls++;
    submittedApprovals.add(approvalJson);
    return submitResult;
  }
}
