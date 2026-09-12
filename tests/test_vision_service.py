"""
Unit tests for VisionService and Vision Analysis Endpoints
"""

import pytest
import asyncio
from app.services.vision_service import VisionService

@pytest.mark.asyncio
async def test_vision_service_fallback():
    service = VisionService()
    # Test with dummy 1x1 GIF base64
    dummy_base64 = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
    res = await service.analyze(dummy_base64)
    
    assert isinstance(res, dict)
    assert "threat_detected" in res
    assert "confidence" in res
    assert "threat_type" in res
    assert "analysis_details" in res

@pytest.mark.asyncio
async def test_vision_service_bytes_input():
    service = VisionService()
    dummy_bytes = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    res = await service.analyze(dummy_bytes, context="Digital arrest suspect police uniform")
    
    assert isinstance(res, dict)
    assert res["confidence"] >= 0
