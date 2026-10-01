import 'error_code.dart';

/// Result of Streaming.verify.
class VerifyReport {
  VerifyReport(this.ok, this.error);

  final bool ok;
  final ErrorCode? error;
}
