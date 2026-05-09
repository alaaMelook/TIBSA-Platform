"""
Validation logic for AI malware analysis input.
"""
from typing import Any

class ScanValidationError(Exception):
    """Raised when scan data fails schema validation (fields, types, ranges)."""
    def __init__(self, errors: list[str]):
        self.errors = errors

def validate_scan_json(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """
    Validates scan JSON data against the required schema.
    Returns a tuple of (clean_data, warnings) or raises ScanValidationError.
    """
    errors: list[str] = []
    warnings: list[str] = []
    clean_data: dict[str, Any] = {}

    if not isinstance(data, dict):
        raise ScanValidationError(["Input must be a JSON object"])

    # Required fields validation
    required_fields = {
        "file_name": str,
        "file_type": str,
        "detections": list,
        "detection_count": int,
        "yara_matches": list,
        "capa_behaviors": list,
        "threat_score": int,
    }

    # Check for extra fields
    extra_fields = set(data.keys()) - set(required_fields.keys())
    if extra_fields:
        errors.append(f"Invalid extra fields found: {', '.join(extra_fields)}")

    for field, expected_type in required_fields.items():
        if field not in data:
            errors.append(f"Missing required field: {field}")
            continue
        
        value = data[field]
        if value is None:
            errors.append(f"Field '{field}' must not be null")
            continue

        # In Python, bool is a subclass of int, so we need to check explicitly
        if expected_type is int and isinstance(value, bool):
            errors.append(f"Field '{field}' must be a int, got bool")
            continue

        if not isinstance(value, expected_type):
            type_name = type(value).__name__
            expected_name = "array" if expected_type is list else "integer" if expected_type is int else expected_type.__name__
            errors.append(f"Field '{field}' must be a {expected_name}, got {type_name}")
            continue

        clean_data[field] = value

    # If basic type checks failed, return early
    if errors:
        raise ScanValidationError(errors)

    # Detailed validations
    
    # 1. Array item types
    array_fields = ["detections", "yara_matches", "capa_behaviors"]
    for field in array_fields:
        bad_indices = [i for i, item in enumerate(clean_data[field]) if not isinstance(item, str)]
        if bad_indices:
            indices_str = ", ".join(map(str, bad_indices))
            errors.append(f"Field '{field}' contains non-string items at positions: {indices_str}")

    # 2. Numeric ranges
    threat_score = clean_data.get("threat_score")
    if isinstance(threat_score, int):
        if threat_score < 0 or threat_score > 100:
            errors.append(f"Field 'threat_score' must be between 0 and 100, got {threat_score}")

    detection_count = clean_data.get("detection_count")
    if isinstance(detection_count, int):
        if detection_count < 0:
            errors.append(f"Field 'detection_count' must be >= 0, got {detection_count}")

    if errors:
        raise ScanValidationError(errors)

    return clean_data, warnings
