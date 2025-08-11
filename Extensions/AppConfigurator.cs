//
// Archivo: AppConfigurator.cs (Proyecto ApiSecureBank)
// Descripci�n: Clase que configura servicios y el pipeline de la aplicaci�n.
//
using ApiSecureBank.DBContext;
using ApiSecureBank.Endpoints;
using ApiSecureBank.Repositories;
using ApiSecureBank.Services;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SecureApi.Endpoints;
using Serilog;
using Serilog.Events;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
// --- CORRECCI�N: Se agrega un alias para resolver la ambig�edad del tipo ILogger ---
using ILogger = Microsoft.Extensions.Logging.ILogger;

/// <summary>
/// Clase que contiene la l�gica modular de configuraci�n de la aplicaci�n,
/// separando la configuraci�n de servicios y el pipeline de solicitudes.
/// </summary>
public static class AppConfigurator
{
    /// <summary>
    /// Configura los servicios de la aplicaci�n.
    /// </summary>
    public static WebApplicationBuilder ConfigureServices(WebApplicationBuilder builder)
    {
        // 1. Configuraci�n de Logging con Serilog
        builder.Services.AddLogging();
        try
        {
            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(builder.Configuration)
                .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
                .MinimumLevel.Override("System", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.Console()
                .CreateLogger();

            builder.Host.UseSerilog();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Error fatal al configurar Serilog. Asegurese de que todas las dependencias (sinks) esten disponibles.");
            throw;
        }

        // --- CORRECCI�N: Registra el ILogger no gen�rico para que pueda ser inyectado ---
        builder.Services.AddSingleton(typeof(ILogger), sp => sp.GetRequiredService<ILogger<Program>>());
        // ----------------------------------------------------------------------------------

        // 2. Configuraci�n de Fuentes de Configuraci�n con Azure Key Vault (solo en producci�n)
        if (!builder.Environment.IsDevelopment())
        {
            var keyVaultUrl = builder.Configuration["KeyVault:VaultUrl"];
            if (!string.IsNullOrEmpty(keyVaultUrl))
            {
                try
                {
                    var keyVaultUri = new Uri(keyVaultUrl);
                    var credential = new DefaultAzureCredential();
                    builder.Configuration.AddAzureKeyVault(keyVaultUri, credential);
                    Log.Information("Azure Key Vault configurado como fuente de configuraci�n.");
                }
                catch (Exception ex)
                {
                    Log.Fatal(ex, "Error fatal al configurar Azure Key Vault. La aplicaci�n no podr� iniciar.");
                    throw;
                }
            }
            else
            {
                Log.Warning("KeyVault:Url no esta configurado. Azure Key Vault no se agregar�.");
            }
        }

        // 3. Configuraci�n de Servicios (Dependency Injection Container)
        if (builder.Environment.IsDevelopment())
        {
            IdentityModelEventSource.ShowPII = true;
        }

        try
        {
            builder.Services.AddDistributedMemoryCache();

            try
            {
                var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
                if (string.IsNullOrEmpty(connectionString))
                {
                    Log.Fatal("La cadena de conexi�n 'DefaultConnection' no esta configurada. La aplicaci�n no puede iniciar.");
                    throw new InvalidOperationException("Connection string 'DefaultConnection' is missing.");
                }

                builder.Services.AddDbContext<ApplicationDBContext>(options =>
                    options.UseSqlServer(connectionString));
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Error fatal al configurar la base de datos. Verifique la cadena de conexi�n.");
                throw;
            }

            builder.Services.AddOutputCache();
            builder.Services.AddEndpointsApiExplorer();

            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo { Title = "ApiSecureBank", Version = "v1" });
                options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    In = ParameterLocation.Header,
                    Description = "Por favor, introduce un token JWT v�lido. Ejemplo: 'Bearer {token}'",
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    BearerFormat = "JWT",
                    Scheme = "bearer"
                });
                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] {}
                    }
                });
            });

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddAutoMapper(cfg => { cfg.AddMaps(typeof(Program).Assembly); });

            builder.Services.AddScoped<IAccountsRepository, AccountsRepository>();
            builder.Services.AddScoped<ICustomersRepository, CustomersRepository>();
            builder.Services.AddScoped<IInterestRatesRepository, InterestRatesRepository>();

            var keyVaultUrl = builder.Configuration["KeyVault:VaultUrl"];
            if (!string.IsNullOrEmpty(keyVaultUrl))
            {
                builder.Services.AddSingleton(sp =>
                {
                    var keyVaultUri = new Uri(keyVaultUrl);
                    var credential = new DefaultAzureCredential();
                    return new KeyClient(keyVaultUri, credential);
                });
            }
            else
            {
                Log.Warning("KeyVault:VaultUrl no configurado en appsettings.json. KeyClient no se registrar�.");
            }

            builder.Services.AddScoped<IKeyVaultService, KeyVaultService>();
            builder.Services.AddScoped<ISecureDataService, SecureDataService>();

            builder.Services.AddAzureDataProtection(builder.Configuration, builder.Environment);

            // --- C�DIGO AGREGADO PARA LA VALIDACI�N DE AUDIENCIA ---
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));

            builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                var allowedAudience = builder.Configuration.GetSection("AzureAd:Audience").Get<string>();

                if (!string.IsNullOrEmpty(allowedAudience))
                {
                    options.TokenValidationParameters.ValidAudiences = new[] { allowedAudience };
                    options.TokenValidationParameters.ValidateAudience = true;
                }

                // Otras validaciones (emisor, vida �til, etc.)
                options.TokenValidationParameters.ValidateLifetime = true;
            });
            // --- FIN DEL C�DIGO AGREGADO ---

            builder.Services.AddAuthorization(options =>
            {
                options.AddPolicy("RequireAdminRole", policy =>
                {
                    policy.RequireRole("Admin");
                });
            });

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("DefaultPolicy",
                    policy =>
                    {
                        policy.WithOrigins("https://securebankappnet-ejdveyfqhxhuafgn.eastus2-01.azurewebsites.net")
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials();
                    });
            });

            builder.Services.AddAppHttpClientWithPolly();
            builder.Services.AddHealthChecks();
            builder.Services.AddControllers();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Error fatal al configurar los servicios de la aplicaci�n.");
            throw;
        }

        return builder;
    }

    /// <summary>
    /// Configura el pipeline de solicitudes HTTP.
    /// </summary>
    public static WebApplication ConfigurePipeline(WebApplication app)
    {
        Log.Information("SecureApi iniciandose...");

        try
        {
            app.UseSerilogRequestLogging(options =>
            {
                options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
                options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
                {
                    diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value);
                    diagnosticContext.Set("RequestScheme", httpContext.Request.Scheme);
                    diagnosticContext.Set("UserAgent", httpContext.Request.Headers["User-Agent"].FirstOrDefault());
                    if (httpContext.User.Identity?.IsAuthenticated == true)
                    {
                        diagnosticContext.Set("UserName", httpContext.User.Identity.Name);
                    }
                };
            });

            app.UseSwagger();
            app.UseSwaggerUI();

            app.UseCors("DefaultPolicy");

            app.UseHsts();
            app.UseCustomSecurityHeaders();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapGet("/", () => "Hello World!")
               .AllowAnonymous();

            // Aqu� se corrige la llamada para que sea un grupo de endpoints
            // y no cause ambig�edad.
            app.MapGroup("/Accounts").MapAccounts().RequireAuthorization();
            app.MapGroup("/Customers").MapCustomers().RequireAuthorization();
            app.MapGroup("/InterestRates").MapInterestRates().RequireAuthorization();
            app.MapGroup("/secure").MapSecureEndpoints();

            app.MapGet("/securedata", (HttpContext context) =>
            {
                var user = context.User;
                var claims = user.Claims.ToDictionary(c => c.Type, c => c.Value);
                return Results.Ok(new
                {
                    Message = "Datos seguros obtenidos exitosamente.",
                    User = user.Identity?.Name ?? "Usuario anonimo",
                    Claims = claims,
                    Timestamp = DateTime.UtcNow
                });
            })
            .WithName("GetSecureData")
            .WithOpenApi()
            .RequireAuthorization();

            app.MapHealthChecks("/health").AllowAnonymous();
            app.MapControllers();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "La aplicaci�n fall� al iniciar o durante la ejecuci�n.");
            throw;
        }

        return app;
    }
}
