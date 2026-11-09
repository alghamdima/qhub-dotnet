# global.json is left out on purpose: it pins a local SDK feature band the sdk:10.0 image may not carry.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY src/Qhub/Qhub.csproj src/Qhub/
RUN dotnet restore src/Qhub/Qhub.csproj
COPY src/Qhub/ src/Qhub/
RUN dotnet publish src/Qhub/Qhub.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENV QHUB_PORT=8080 QHUB_DATA_DIR=/data
RUN mkdir /data && chown app:app /data
USER app
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["dotnet", "Qhub.dll"]
