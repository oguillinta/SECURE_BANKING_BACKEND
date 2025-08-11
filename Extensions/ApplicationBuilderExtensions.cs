using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Serilog;
using System.Threading.Tasks;

/// <summary>
/// Proporciona mtodos de extensin para configurar el pipeline de solicitudes en IApplicationBuilder.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Aade encabezados de seguridad personalizados al pipeline de la aplicacin.
    /// </summary>
    public static IApplicationBuilder UseCustomSecurityHeaders(this IApplicationBuilder app)
    {
        app.Use(async (context, next) =>
        {
            context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Append("X-Frame-Options", "DENY");
            context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
            context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';");
            await next();
        });
        Log.Information("Middleware de encabezados de seguridad personalizados agregados.");
        return app;
    }
}