import cv2
import numpy as np
from typing import Dict, Any
from .url_engine import analyze_url
from .nlp_engine import analyze_message

qr_detector = cv2.QRCodeDetector()

def decode_and_analyze_qr(image_bytes: bytes) -> Dict[str, Any]:
    """Decodes a QR code from image bytes and routes the payload to the threat pipeline."""
    # Convert image bytes to numpy array
    nparr = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if image is None:
        return {
            "success": False,
            "error": "Invalid image file. Could not decode image format.",
            "scan_type": "qr"
        }

    decoded_info, points, _ = qr_detector.detectAndDecode(image)

    if not decoded_info or not decoded_info.strip():
        return {
            "success": False,
            "error": "No QR code could be detected in the provided image. Please check image clarity.",
            "scan_type": "qr"
        }

    payload = decoded_info.strip()

    # Determine if QR contains a URL or plain text
    is_url = payload.startswith(("http://", "https://", "www.")) or ("." in payload and "/" in payload)

    if is_url:
        result = analyze_url(payload)
        result["scan_type"] = "qr"
        result["extracted_payload"] = payload
        result["payload_type"] = "URL (Quishing Target)"
        result["findings"].insert(0, {
            "indicator": "QR Code Extracted URL (Quishing Analysis)",
            "severity": "INFO",
            "description": f"QR Code successfully decoded to destination: {payload}. Passed into URL deep inspection pipeline."
        })
    else:
        result = analyze_message(payload)
        result["scan_type"] = "qr"
        result["extracted_payload"] = payload
        result["payload_type"] = "Text / Data Payload"
        result["findings"].insert(0, {
            "indicator": "QR Code Extracted Text",
            "severity": "INFO",
            "description": f"QR Code decoded to text payload ({len(payload)} characters). Analyzed for social engineering cues."
        })

    result["success"] = True
    return result
