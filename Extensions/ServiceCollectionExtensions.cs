using ApiSecureBank.Services;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;
using Polly;
using Polly.Extensions.Http;
using Serilog;
using System;
using System.Net.Http;

/// <summary>
/// Proporciona mtodos de extensin para configurar servicios en IServiceCollection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Configura Data Protection para usar Azure Key Vault y Azure Blob Storage en entornos de produccin.
    /// </summary>
    public static IServiceCollection AddAzureDataProtection(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        if (!environment.IsDevelopment())
        {
            var keyVaultUrl = configuration["KeyVault:VaultUrl"];
            // Se corrige la forma de leer la cadena de conexin para Data Protection
            // Ahora lee directamente de "DataProtection:StorageConnectionString" en lugar de ConnectionStrings
            var storageConnectionString = configuration["DataProtection:StorageConnectionString"];

            if (string.IsNullOrEmpty(keyVaultUrl))
            {
                Log.Warning("KeyVault:VaultUrl no est configurado. Data Protection no proteger las claves.");
            }
            if (string.IsNullOrEmpty(storageConnectionString))
            {
                Log.Warning("DataProtection:StorageConnectionString no est configurado. Data Protection no persistir las claves.");
            }

            try
            {
                var dataProtectionBuilder = services.AddDataProtection();
                var credential = new DefaultAzureCredential();

                if (!string.IsNullOrEmpty(storageConnectionString))
                {
                    dataProtectionBuilder.PersistKeysToAzureBlobStorage(storageConnectionString, "keys", "dataprotection-keys");
                    Log.Information("Data Protection configurado para persistir claves en Azure Blob Storage.");
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error al configurar Data Protection.");
            }
        }
        else
        {
            Log.Information("Entorno de desarrollo detectado. Data Protection no se configurar.");
        }
        return services;
    }

    /// <summary>
    /// Configura la autenticacin y autorizacin de la aplicacin usando Microsoft Identity.
    /// </summary>
    public static IServiceCollection AddAppAuthenticationAndAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddMicrosoftIdentityWebApi(configuration.GetSection("AzureAd"))
        .EnableTokenAcquisitionToCallDownstreamApi(options => configuration.Bind("AzureAd", options))
        .AddInMemoryTokenCaches();

        services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
            options.AddPolicy("RequireAdminRole", policy =>
                policy.RequireRole("Admin"));
        });
        Log.Information("Autenticacin y autorizacin configuradas.");
        return services;
    }

    /// <summary>
    /// Configura la poltica de CORS para la aplicacin.
    /// </summary>
    public static IServiceCollection AddAppCors(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("DefaultPolicy", policy =>
            {
                var allowedOrigins = configuration.GetSection("Security:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
                if (allowedOrigins.Length == 0)
                {
                    Log.Warning("No se han configurado AllowedOrigins. La poltica CORS podra ser demasiado restrictiva o permisiva.");
                }
                else
                {
                    Log.Information("Orgenes CORS permitidos: {AllowedOrigins}", string.Join(", ", allowedOrigins));
                }

                policy.WithOrigins(allowedOrigins)
                        .AllowAnyHeader()
                        .AllowAnyMethod()
                        .AllowCredentials();
            });
        });
        Log.Information("CORS configurado con 'DefaultPolicy'.");
        return services;
    }

    /// <summary>
    /// Configura un HttpClient con polticas de reintento y circuit breaker de Polly.
    /// </summary>
    public static IServiceCollection AddAppHttpClientWithPolly(this IServiceCollection services)
    {
        services.AddHttpClient("ResilientClient", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
        })
        .AddPolicyHandler(PollyPolicies.GetRetryPolicy())
        .AddPolicyHandler(PollyPolicies.GetCircuitBreakerPolicy());
        Log.Information("HttpClient 'ResilientClient' configurado con polticas de Polly.");
        return services;
    }
}