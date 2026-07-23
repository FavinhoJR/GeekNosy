import pytest

from app.target_policy import TargetPolicyError, normalize_and_validate_domain, validate_url


@pytest.mark.asyncio
async def test_blocks_loopback_and_private_targets():
    with pytest.raises(TargetPolicyError, match="bloqueado"):
        await normalize_and_validate_domain("127.0.0.1")
    with pytest.raises(TargetPolicyError, match="bloqueado"):
        await normalize_and_validate_domain("10.10.10.10")


@pytest.mark.asyncio
async def test_accepts_public_literal_and_normalizes():
    target = await normalize_and_validate_domain("https://8.8.8.8/path")
    assert target.hostname == "8.8.8.8"
    assert target.normalized_url == "https://8.8.8.8/"


@pytest.mark.asyncio
async def test_rejects_credentials_ports_and_cross_host_redirects():
    with pytest.raises(TargetPolicyError, match="credenciales"):
        await validate_url("https://user:pass@8.8.8.8/")
    with pytest.raises(TargetPolicyError, match="Puerto"):
        await validate_url("https://8.8.8.8:8443/")
    with pytest.raises(TargetPolicyError, match="salió"):
        await validate_url("https://8.8.8.8/", expected_host="1.1.1.1")
