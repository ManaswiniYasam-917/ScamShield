import numpy as np
from PIL import Image
from io import BytesIO

try:
    import cv2
except Exception:
    cv2 = None

def decode_qr_image(image_bytes: bytes) -> dict:
    try:
        pil_img = Image.open(BytesIO(image_bytes)).convert("RGB")
        img_np = np.array(pil_img)

        if cv2 is not None:
            img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
            detector = cv2.QRCodeDetector()
            data, points, _ = detector.detectAndDecode(img_cv)

            if not data and points is not None:
                gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
                data, points, _ = detector.detectAndDecode(gray)

            if data:
                return {
                    "success": True,
                    "payload": data.strip(),
                    "width": pil_img.width,
                    "height": pil_img.height,
                    "details": f"Decoded QR matrix ({pil_img.width}x{pil_img.height} px)"
                }
            else:
                return {
                    "success": False,
                    "payload": "",
                    "details": "No readable QR code pattern detected in the uploaded image."
                }
        else:
            return {
                "success": False,
                "payload": "",
                "details": "OpenCV library is not available in current serverless environment."
            }
    except Exception as exc:
        return {
            "success": False,
            "payload": "",
            "details": f"QR decode error: {str(exc)}"
        }
