import os
import httpx

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_USERINFO_URL = (
    "https://www.googleapis.com/oauth2/v3/userinfo"
)
GOOGLE_TOKEN_INFO_URL = (
    "https://oauth2.googleapis.com/tokeninfo"
)


async def verify_google_token(credential: str) -> dict:
    """
    Accepts either:
    - A Google id_token (JWT string)
    - A Google access_token (opaque string)
    Tries userinfo endpoint first, falls back to tokeninfo.
    """
    async with httpx.AsyncClient(timeout=10) as client:

        # Try as access_token via userinfo endpoint
        try:
            resp = await client.get(
                GOOGLE_USERINFO_URL,
                headers={
                    "Authorization": f"Bearer {credential}"
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "google_id":      data.get("sub"),
                    "email":          data.get("email"),
                    "full_name":      data.get("name", ""),
                    "avatar_url":     data.get("picture"),
                    "email_verified": data.get(
                        "email_verified", False
                    ),
                }
        except Exception:
            pass

        # Fall back to id_token verification
        resp = await client.get(
            GOOGLE_TOKEN_INFO_URL,
            params={"id_token": credential},
        )
        if resp.status_code != 200:
            raise ValueError(
                "Invalid Google credential"
            )

        data = resp.json()
        if "error_description" in data:
            raise ValueError(data["error_description"])

        return {
            "google_id":      data.get("sub"),
            "email":          data.get("email"),
            "full_name":      data.get("name", ""),
            "avatar_url":     data.get("picture"),
            "email_verified": data.get(
                "email_verified", "false"
            ) == "true",
        }
