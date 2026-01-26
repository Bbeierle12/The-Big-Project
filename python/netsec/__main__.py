import uvicorn

from netsec.core.config import get_settings


def main():
    settings = get_settings()
    uvicorn.run(
        "netsec.api.app:create_app",
        factory=True,
        host=settings.server.host,
        port=settings.server.port,
        reload=settings.server.reload,
        workers=settings.server.workers,
    )


if __name__ == "__main__":
    main()
