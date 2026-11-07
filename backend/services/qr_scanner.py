"""
TRUSTX AI - Module H: QR Code Phishing Scanner
Decodes QR code images using OpenCV / pyzbar, extracts embedded URLs,
traces redirect destinations, and submits to the investigation engine.
"""

import io
import requests
import urllib.parse
from typing import Dict, Any, Optional
import numpy as np
from PIL import Image

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False


def decode_qr_image_bytes(image_bytes: bytes) -> Dict[str, Any]:
    """
    Decode a QR code from raw image bytes.
    Tries pyzbar first, then OpenCV QRCodeDetector fallback.
    """
    result = {
        "success": False,
        "raw_text": None,
        "is_url": False,
        "extracted_url": None,
        "redirect_hops": [],
        "final_destination": None,
        "error": None
    }

    try:
        # Load image with PIL
        pil_image = Image.open(io.BytesIO(image_bytes))
        
        # 1. Try pyzbar
        if HAS_PYZBAR:
            decoded_objects = pyzbar_decode(pil_image)
            if decoded_objects:
                result["raw_text"] = decoded_objects[0].data.decode('utf-8', errors='ignore')
                result["success"] = True

        # 2. Try OpenCV fallback if pyzbar didn't find anything
        if not result["success"] and HAS_CV2:
            open_cv_image = np.array(pil_image.convert('RGB'))
            # Convert RGB to BGR
            open_cv_image = open_cv_image[:, :, ::-1].copy()
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(open_cv_image)
            if data:
                result["raw_text"] = data
                result["success"] = True

        if not result["success"]:
            result["error"] = "No QR code could be detected in the provided image."
            return result

        raw_text = result["raw_text"].strip()
        # Check if text is a URL
        if raw_text.startswith(('http://', 'https://')) or ('.' in raw_text and not ' ' in raw_text):
            result["is_url"] = True
            normalized_url = raw_text if raw_text.startswith(('http://', 'https://')) else 'https://' + raw_text
            result["extracted_url"] = normalized_url

            # Trace redirect chain to uncover shortened URLs
            try:
                resp = requests.head(
                    normalized_url,
                    allow_redirects=True,
                    timeout=4.0,
                    headers={'User-Agent': 'TRUSTX-AI-QRScanner/1.0'}
                )
                result["final_destination"] = resp.url
                for r in resp.history:
                    result["redirect_hops"].append({
                        "from": r.url,
                        "status": r.status_code,
                        "to": r.headers.get('Location', '')
                    })
            except Exception:
                result["final_destination"] = normalized_url
        else:
            result["is_url"] = False

    except Exception as e:
        result["error"] = f"Error processing QR image: {str(e)}"

    return result
