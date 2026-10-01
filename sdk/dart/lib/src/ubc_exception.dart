import 'error_code.dart';

/// A UBC failure carrying a portable, stable error identifier.
class UbcException implements Exception {
  const UbcException(this.code);

  final ErrorCode code;

  @override
  String toString() => code.stableId;
}
