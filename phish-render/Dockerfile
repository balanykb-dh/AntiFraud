# syntax=docker/dockerfile:1

# ---- build ----
# Works on x64 VPS and on arm64 (Apple Silicon Mac, ARM VPS): the runtime id follows the target arch.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS build
ARG TARGETARCH
WORKDIR /src
COPY src/RenderService/RenderService.csproj src/RenderService/
RUN if [ "$TARGETARCH" = "arm64" ]; then echo linux-arm64 > /rid; else echo linux-x64 > /rid; fi \
 && dotnet restore src/RenderService/RenderService.csproj -r "$(cat /rid)"
COPY src/ src/
RUN dotnet publish src/RenderService/RenderService.csproj \
      -c Release -r "$(cat /rid)" --self-contained false --no-restore -o /app

# ---- runtime ----
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS final
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DOTNET_EnableDiagnostics=0 \
    HOME=/tmp
WORKDIR /app
COPY --from=build /app .

# Chromium + system libraries, version-matched to the Microsoft.Playwright package.
ARG DEBIAN_FRONTEND=noninteractive
RUN chmod -R a+rx /app/.playwright \
 && dotnet RenderService.dll install-browsers \
 && chmod -R a+rx /ms-playwright \
 && rm -rf /var/lib/apt/lists/*

# Non-root user that ships with the .NET images.
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "RenderService.dll"]
