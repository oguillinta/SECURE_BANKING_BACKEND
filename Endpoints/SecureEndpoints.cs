using ApiSecureBank.Extensions;
using ApiSecureBank.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using SecureApi.Endpoints;
using System.Diagnostics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecureApi.Endpoints;

// Un tipo de marcador para usar con ILogger<T>
public class SecureEndpointsMarker { }

// La clase es est&aacute;tica para poder contener el m&eacute;todo de extensi&oacute;n.
public static class SecureEndpoints
{
    // M&eacute;todo de extensi&oacute;n para agrupar y proteger los endpoints.
    public static RouteGroupBuilder MapSecureEndpoints(this RouteGroupBuilder group)
    {
        group.AddEndpointFilter<ExceptionHandlingFilter>();
        group.RequireAuthorization();

        group.MapPost("/change-storage-type", ChangeStorageType);
        group.MapPost("/test-protection", TestProtection);
        group.MapGet("/key-vault-secrets", GetKeyVaultSecrets);
        group.MapPost("/create-secret", CreateSecret);
        group.MapGet("/key-vault-status", CheckKeyVaultStatus);
        group.MapGet("/test-configuration", TestConfiguration);
        group.MapGet("/diagnostics", TestConfiguration); // Reusa el mismo m&eacute;todo
        group.MapPost("/test-cross-decryption", TestCrossDecryption);


        return group;
    }

    /// <summary>
    /// Obtiene informaci&oacute;n del usuario autenticado.
    /// </summary>
    public static Ok<UserInfoResponse> GetUserInfo(
        ClaimsPrincipal user,
        ILogger<SecureEndpointsMarker> logger)
    {
        var userInfo = new UserInfoResponse(
            UserId: user.FindFirst(ClaimTypes.NameIdentifier)?.Value,
            Name: user.FindFirst(ClaimTypes.Name)?.Value ?? user.FindFirst("name")?.Value,
            Email: user.FindFirst(ClaimTypes.Email)?.Value ?? user.FindFirst("preferred_username")?.Value,
            Roles: user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray(),
            Claims: user.Claims.Select(c => new { Type = c.Type, Value = c.Value }).ToArray(),
            IsAuthenticated: user.Identity?.IsAuthenticated ?? false,
            AuthenticationType: user.Identity?.AuthenticationType,
            Timestamp: DateTime.UtcNow
        );

        logger.LogInformation("Informaci&oacute;n de usuario solicitada por {UserId}", userInfo.UserId);
        return TypedResults.Ok(userInfo);
    }

    /// <summary>
    /// Endpoint que requiere rol de administrador.
    /// </summary>
    public static Ok<AdminDataResponse> GetAdminData(
        ILogger<SecureEndpointsMarker> logger, HttpContext httpContext)
    {
        var adminData = new AdminDataResponse(
            Message: "Datos administrativos sensibles",
            SystemInfo: new
            {
                Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
                MachineName = Environment.MachineName,
                ProcessorCount = Environment.ProcessorCount,
                WorkingSet = Environment.WorkingSet,
                Version = Environment.Version.ToString()
            },
            RequestInfo: new
            {
                RequestId = httpContext.TraceIdentifier,
                RequestTime = DateTime.UtcNow,
                ClientIP = httpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = httpContext.Request.Headers["User-Agent"].ToString()
            },
            Timestamp: DateTime.UtcNow
        );

        logger.LogInformation("Datos administrativos accedidos por {UserId}",
            httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value);

        return TypedResults.Ok(adminData);
    }

    /// <summary>
    /// Endpoint para probar la configuraci&oacute;n de Key Vault.
    /// </summary>
    public static Ok<KeyVaultTestResponse> TestKeyVault(
        ILogger<SecureEndpointsMarker> logger, IConfiguration configuration, ClaimsPrincipal user)
    {
        var testSecret = configuration["TestSecret"] ?? "No configurado";
        var keyVaultUrl = configuration["KeyVault:VaultUrl"];

        var result = new KeyVaultTestResponse(
            Message: "Prueba de conectividad con Key Vault",
            KeyVaultConfigured: !string.IsNullOrEmpty(keyVaultUrl),
            KeyVaultUrl: string.IsNullOrEmpty(keyVaultUrl) ? "No configurado" : keyVaultUrl,
            // AQU&Iacute; EST&Aacute; EL CAMBIO: Se usa ':' en lugar de '='
            TestSecretExists: testSecret != "No configurado",
            Environment: Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
            Timestamp: DateTime.UtcNow
        );

        logger.LogInformation("Prueba de Key Vault ejecutada por {UserId}",
            user.FindFirst(ClaimTypes.NameIdentifier)?.Value);

        return TypedResults.Ok(result);
    }

    /// <summary>
    /// Endpoint para verificar pol&iacute;ticas de resiliencia.
    /// </summary>
    public static async Task<Ok<ResilienceTestResponse>> TestResilience(
       ILogger<SecureEndpointsMarker> logger, IHttpClientFactory httpClientFactory, ClaimsPrincipal user)
    {
        var httpClient = httpClientFactory.CreateClient("ResilientClient");
        var testUrls = new[] { "https://httpbin.org/status/200", "https://httpbin.org/delay/1", "https://httpbin.org/status/500" };
        var results = new List<object>();
        var stopwatch = Stopwatch.StartNew();

        foreach (var url in testUrls)
        {
            results.Add(await ExecuteResilientRequest(httpClient, url));
        }

        stopwatch.Stop();
        logger.LogInformation("Prueba de resiliencia ejecutada por {UserId} en {ElapsedMilliseconds}ms",
            user.FindFirst(ClaimTypes.NameIdentifier)?.Value, stopwatch.ElapsedMilliseconds);

        var response = new ResilienceTestResponse(
            Message: "Prueba de pol&iacute;ticas de resiliencia completada",
            Results: results,
            Timestamp: DateTime.UtcNow
        );

        return TypedResults.Ok(response);
    }

    private static async Task<object> ExecuteResilientRequest(HttpClient httpClient, string url)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();
            var httpResponse = await httpClient.GetAsync(url);
            stopwatch.Stop();

            return new
            {
                Url = url,
                StatusCode = (int)httpResponse.StatusCode,
                Success = httpResponse.IsSuccessStatusCode,
                ExecutionTime = stopwatch.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            return new
            {
                Url = url,
                Error = ex.Message,
                Success = false,
                ExecutionTime = -1
            };
        }
    }
    public static IResult ChangeStorageType(
        [FromBody] StorageChangeRequest request,
        HttpContext httpContext,
        ILogger<SecureEndpointsMarker> logger)
    {
        if (request == null)
        {
            return Results.BadRequest(new { success = false, error = "Solicitud inv&aacute;lida" });
        }

        // Almacenar preferencia en sesi&oacute;n (si est&aacute; configurada)
        httpContext.Session.SetString("StorageType", request.UseAzureStorage ? "Azure" : "Local");

        try
        {
            var preferencePath = Path.Combine(Directory.GetCurrentDirectory(), "storage-preference.json");
            var preference = new
            {
                UseAzureStorage = request.UseAzureStorage,
                LastChanged = DateTime.UtcNow,
                ChangedBy = httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
            };

            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(preferencePath, JsonSerializer.Serialize(preference, jsonOptions));
            logger.LogInformation("Storage preference saved to file: {Preference}", request.UseAzureStorage ? "Azure" : "Local");
        }
        catch (Exception fileEx)
        {
            logger.LogWarning("Could not save preference to file: {Error}", fileEx.Message);
        }

        var storageType = request.UseAzureStorage ? "Azure Storage + Key Vault" : "Local File System";
        var description = request.UseAzureStorage
            ? "Usando Azure Blob Storage + Key Vault para testing completo"
            : "Usando sistema de archivos local para desarrollo";

        logger.LogInformation("Storage type preference changed to: {StorageType}", storageType);

        return Results.Json(new
        {
            success = true,
            storageType = storageType,
            description = description,
            isAzure = request.UseAzureStorage,
            message = $"Preferencia guardada: {storageType}",
            requiresRestart = true,
            note = "⚠️ La aplicaci&oacute;n debe reiniciarse para aplicar este cambio en Data Protection.",
            instruction = "Presiona Ctrl+C en la consola y ejecuta 'dotnet run' nuevamente."
        });
    }

    public static IResult TestProtection(
        [FromBody] TestDataRequest request,
        ISecureDataService secureDataService,
        ILogger<SecureEndpointsMarker> logger)
    {
        try
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Data) || string.IsNullOrWhiteSpace(request.Purpose))
            {
                return Results.BadRequest(new { success = false, error = "Datos de entrada inv&aacute;lidos o vac&iacute;os" });
            }

            logger.LogInformation("Testing protection for data length: {DataLength}, purpose: {Purpose}",
                request.Data.Length, request.Purpose);

            var protectedData = secureDataService.ProtectSensitiveData(request.Data, request.Purpose);

            if (string.IsNullOrEmpty(protectedData))
            {
                logger.LogError("Protected data is null or empty");
                return Results.Problem("Error: Los datos protegidos est&aacute;n vac&iacute;os", statusCode: 500);
            }

            var unprotectedData = secureDataService.UnprotectSensitiveData<string>(protectedData, request.Purpose);

            if (string.IsNullOrEmpty(unprotectedData))
            {
                logger.LogError("Unprotected data is null or empty");
                return Results.Problem("Error: Los datos desprotegidos est&aacute;n vac&iacute;os", statusCode: 500);
            }

            if (unprotectedData != request.Data)
            {
                logger.LogError("Data integrity check failed.");
                return Results.Problem("Error: Fall&oacute; la verificaci&oacute;n de integridad de datos", statusCode: 500);
            }

            logger.LogInformation("Data protection test successful");

            return Results.Ok(new
            {
                success = true,
                originalData = request.Data,
                protectedData = protectedData,
                unprotectedData = unprotectedData,
                protectedLength = protectedData.Length,
                originalLength = request.Data.Length,
                purpose = request.Purpose,
                testTime = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC")
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error in data protection test");
            return Results.Problem($"Error inesperado: {ex.Message}", statusCode: 500);
        }
    }

    public static async Task<IResult> GetKeyVaultSecrets(
        IKeyVaultService keyVaultService,
        ILogger<SecureEndpointsMarker> logger)
    {
        try
        {
            var secrets = await keyVaultService.GetAllSecretsAsync();
            return Results.Ok(new { success = true, secrets = secrets });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error retrieving Key Vault secrets");
            return Results.Problem($"Error: {ex.Message}", statusCode: 500);
        }
    }

    public static async Task<IResult> CreateSecret(
        [FromBody] CreateSecretRequest request,
        IKeyVaultService keyVaultService,
        ILogger<SecureEndpointsMarker> logger)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.SecretName) || string.IsNullOrWhiteSpace(request.SecretValue))
        {
            return Results.BadRequest(new { success = false, error = "Nombre y valor del secret son requeridos" });
        }

        try
        {
            await keyVaultService.SetSecretAsync(request.SecretName, request.SecretValue);
            return Results.Ok(new { success = true, message = $"Secret '{request.SecretName}' creado exitosamente" });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error creating secret: {SecretName}", request?.SecretName);
            return Results.Problem($"Error: {ex.Message}", statusCode: 500);
        }
    }

    public static async Task<IResult> CheckKeyVaultStatus(
        IKeyVaultService keyVaultService,
        ILogger<SecureEndpointsMarker> logger)
    {
        try
        {
            var isConnected = await keyVaultService.IsConnectedAsync();

            if (!isConnected)
            {
                return Results.Json(new
                {
                    success = false,
                    error = "No se puede conectar a Key Vault",
                    connected = false
                });
            }

            var keyVaultInfo = await keyVaultService.GetKeyVaultInfoAsync();
            var secrets = await keyVaultService.GetAllSecretsAsync();

            return Results.Ok(new
            {
                success = true,
                connected = true,
                info = keyVaultInfo,
                secretCount = secrets.Count,
                secrets = secrets,
                message = $"Key Vault conectado exitosamente con {secrets.Count} secret(s)"
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error checking Key Vault status");
            return Results.Problem($"Error: {ex.Message}", statusCode: 500);
        }
    }

    public static IResult TestConfiguration(
        IConfiguration configuration,
        ISecureDataService secureDataService)
    {
        try
        {
            var keyVaultUri = configuration["KeyVault:VaultUri"];
            var hasStorageConnection = !string.IsNullOrEmpty(configuration["DataProtection:StorageConnectionString"]);

            return Results.Ok(new
            {
                success = true,
                message = "Controlador funcionando correctamente",
                timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                applicationName = configuration["DataProtection:ApplicationName"],
                hasStorageConnection = hasStorageConnection,
                hasKeyVault = !string.IsNullOrEmpty(keyVaultUri),
                keyVaultUri = keyVaultUri,
                dataProtectionConfigured = secureDataService != null,
                keyVaultConfigured = true, // Asumimos que si estamos aqu&iacute;, el servicio est&aacute;
                framework = ".NET 9",
                port = "7001",
                laboratory = "Testing Completo"
            });
        }
        catch (Exception ex)
        {
            return Results.Problem($"Error: {ex.Message}", statusCode: 500);
        }
    }

    public static IResult TestCrossDecryption(
        [FromBody] CrossDecryptRequest request,
        ISecureDataService secureDataService,
        ILogger<SecureEndpointsMarker> logger)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.ProtectedData) || string.IsNullOrWhiteSpace(request.Purpose))
        {
            return Results.BadRequest(new { success = false, error = "Solicitud inv&aacute;lida: Datos o prop&oacute;sito faltante" });
        }

        try
        {
            logger.LogInformation("Attempting cross-decryption with purpose: {Purpose}", request.Purpose);
            var unprotectedData = secureDataService.UnprotectSensitiveData<string>(request.ProtectedData, request.Purpose);
            logger.LogInformation("Cross-decryption successful with purpose: {Purpose}");

            return Results.Ok(new
            {
                success = true,
                unprotectedData = unprotectedData,
                purpose = request.Purpose,
                message = "Desencriptaci&oacute;n exitosa"
            });
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning("Cryptographic error (expected for cross-purpose): {Error}", ex.Message);
            return Results.BadRequest(new
            {
                success = false,
                error = "Error criptogr&aacute;fico: Los datos fueron encriptados con un prop&oacute;sito diferente",
                technicalError = ex.Message
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error in cross-decryption test");
            return Results.Problem($"Error inesperado: {ex.Message}", statusCode: 500);
        }
    }
}

// Modelos de solicitud (pueden ir en su propio archivo)
public class TestDataRequest
{
    public string Data { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
}

public class StorageChangeRequest
{
    public bool UseAzureStorage { get; set; }
}

public class CreateSecretRequest
{
    public string SecretName { get; set; } = string.Empty;
    public string SecretValue { get; set; } = string.Empty;
}

public class CrossDecryptRequest
{
    public string ProtectedData { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
}