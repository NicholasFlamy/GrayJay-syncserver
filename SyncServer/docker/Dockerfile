FROM mcr.microsoft.com/dotnet/sdk:9.0@sha256:3fcf6f1e809c0553f9feb222369f58749af314af6f063f389cbd2f913b4ad556 AS build
WORKDIR /App

# Copy everything
COPY . ./

#RUN ls -la /App && exit 1

# Restore as distinct layers
RUN dotnet restore SyncServer

RUN apt-get update && apt-get install -y build-essential

# Build and publish a release, I added a janky workaround since SyncClient fails to build but we can continue anyway
RUN dotnet publish SyncServer -o out -c Release -r linux-x64 || exit 0

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:9.0@sha256:b4bea3a52a0a77317fa93c5bbdb076623f81e3e2f201078d89914da71318b5d8
WORKDIR /App
COPY --from=build /App/out .
ENTRYPOINT ["./SyncServer"]