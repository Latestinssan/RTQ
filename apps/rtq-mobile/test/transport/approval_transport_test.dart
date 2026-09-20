/// Approval-result transport: endpoint shapes, failure mapping, timeouts and
/// fail-closed behavior. Uses a mocked HTTP client so no socket is opened.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:rtq_mobile/transport/approval_transport.dart';

void main() {
  group('startPairing', () {
    test('parses a valid pairing session', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        client: MockClient((request) async {
          expect(request.method, 'POST');
          expect(request.url.path, '/pair/start');
          return http.Response(
            jsonEncode({
              'ok': true,
              'payload': 'rtq://pair?v=1&c=abc',
              'pairingId': 'pair-1',
              'expiresAt': 1750000000000,
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );
      final result = await transport.startPairing();
      expect(result.ok, isTrue);
      expect(result.value!.pairingId, 'pair-1');
      expect(result.value!.expiresAt, 1750000000000);
      expect(result.value!.payload, startsWith('rtq://pair'));
    });

    test('non-200 maps to a transport error', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        client: MockClient((_) async => http.Response('denied', 500)),
      );
      final result = await transport.startPairing();
      expect(result.ok, isFalse);
      expect(result.code, 'transport.http_500');
    });

    test('malformed response maps to malformed_response', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        client: MockClient((_) async => http.Response('nope', 200)),
      );
      final result = await transport.startPairing();
      expect(result.ok, isFalse);
      expect(result.code, 'transport.malformed_response');
    });

    test('connection failure is a denial, not an exception', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:1'),
        client: MockClient((_) async => throw const SocketException('down')),
      );
      final result = await transport.startPairing();
      expect(result.ok, isFalse);
      expect(result.code, 'transport.connection_error');
    });
  });

  group('completePairing', () {
    test('returns deviceId on success', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        client: MockClient((request) async {
          expect(request.url.path, '/pair/complete');
          return http.Response(
            jsonEncode({'ok': true, 'deviceId': 'dev-123', 'name': 'n'}),
            200,
          );
        }),
      );
      final result = await transport.completePairing('{"x":1}');
      expect(result.ok, isTrue);
      expect(result.value, 'dev-123');
    });

    test('failure reason travels back', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        client: MockClient(
          (_) async => http.Response(
            jsonEncode({
              'ok': false,
              'code': 'pairing.signature_invalid',
              'reason': 'bad sig',
            }),
            400,
          ),
        ),
      );
      final result = await transport.completePairing('{}');
      expect(result.ok, isFalse);
      expect(result.code, 'pairing.signature_invalid');
      expect(result.reason, 'bad sig');
    });
  });

  group('submitApproval', () {
    test('submits the raw JSON body and returns challengeId', () async {
      String? seenBody;
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        client: MockClient((request) async {
          expect(request.url.path, '/approve');
          seenBody = request.body;
          return http.Response(
            jsonEncode({
              'ok': true,
              'challengeId': 'c-1',
              'capability': 'files.delete',
              'deviceId': 'dev-1',
            }),
            200,
          );
        }),
      );
      final result = await transport.submitApproval('{"decision":"granted"}');
      expect(result.ok, isTrue);
      expect(result.value, 'c-1');
      expect(seenBody, '{"decision":"granted"}');
    });

    test('host decision denial surfaces the code', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        client: MockClient(
          (_) async => http.Response(
            jsonEncode({
              'ok': false,
              'code': 'approval.decision_denied',
              'reason': 'device denied',
            }),
            400,
          ),
        ),
      );
      final result = await transport.submitApproval('{}');
      expect(result.ok, isFalse);
      expect(result.code, 'approval.decision_denied');
    });

    test('timeout maps to transport.timeout', () async {
      final transport = HttpApprovalTransport(
        baseUrl: Uri.parse('http://127.0.0.1:8787'),
        timeout: const Duration(milliseconds: 50),
        client: MockClient((_) async {
          await Future<void>.delayed(const Duration(milliseconds: 500));
          return http.Response('{}', 200);
        }),
      );
      final result = await transport.submitApproval('{}');
      expect(result.ok, isFalse);
      expect(result.code, 'transport.timeout');
    });
  });

  group('FakeApprovalTransport', () {
    test('records submissions for assertions', () async {
      final fake = FakeApprovalTransport();
      await fake.submitApproval('{"decision":"granted"}');
      expect(fake.submitCalls, 1);
      expect(fake.submittedApprovals.single, '{"decision":"granted"}');
    });
  });
}
