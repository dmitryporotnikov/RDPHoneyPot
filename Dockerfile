# Stage 1: Build & Publish
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY RDPHoney/RDPHoney.csproj RDPHoney/
RUN dotnet restore RDPHoney/RDPHoney.csproj

# Copy remaining source code and publish
COPY RDPHoney/ RDPHoney/
WORKDIR /src/RDPHoney
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/runtime:10.0 AS final
WORKDIR /app

# Ensure data and assets directories exist
RUN mkdir -p /app/data /app/assets

# Copy build artifacts
COPY --from=build /app/publish .

# Copy static assets (desktop.jpg, etc.)
COPY assets/ /app/assets/

# Environment configuration
ENV DATABASE_PATH=/app/data/RdpHoneypotLogs.db \
    HONEYPOT_PORT=3389 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true

# Expose default RDP honeypot port
EXPOSE 3389

# Mountable volume for database persistence and host access
VOLUME ["/app/data"]

ENTRYPOINT ["dotnet", "RDPHoney.dll"]
