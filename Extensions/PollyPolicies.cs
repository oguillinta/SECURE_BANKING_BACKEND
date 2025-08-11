using Polly;
using Polly.Extensions.Http;
using Serilog;
using System;
using System.Net.Http;

/// <summary>
/// Proporciona mtodos auxiliares estticos para definir polticas de Polly.
/// </summary>
public static class PollyPolicies
{
    /// <summary>
    /// Obtiene una poltica de reintento con retroceso exponencial.
    /// </summary>
    public static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy()
    {
        return HttpPolicyExtensions
            .HandleTransientHttpError()
            .OrResult(msg => !msg.IsSuccessStatusCode)
            .WaitAndRetryAsync(
                retryCount: 3,
                sleepDurationProvider: retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
                onRetry: (outcome, timespan, retryCount, context) =>
                {
                    Log.Warning("Reintentando solicitud HTTP a {RequestUri}. Intento {RetryCount}. Retardo de {Delay}ms debido a {StatusCode}.",
                                outcome.Result?.RequestMessage?.RequestUri,
                                retryCount,
                                timespan.TotalMilliseconds,
                                outcome.Result?.StatusCode);
                });
    }

    /// <summary>
    /// Obtiene una poltica de circuit breaker.
    /// </summary>
    public static IAsyncPolicy<HttpResponseMessage> GetCircuitBreakerPolicy()
    {
        return HttpPolicyExtensions
            .HandleTransientHttpError()
            .CircuitBreakerAsync(
                handledEventsAllowedBeforeBreaking: 5,
                durationOfBreak: TimeSpan.FromSeconds(30),
                onBreak: (exception, duration) =>
                {
                    Log.Error(exception.Exception, "Circuit breaker abierto por {Duration}ms. Causa: {ExceptionMessage}",
                              duration.TotalMilliseconds,
                              exception.Exception?.Message);
                },
                onReset: () =>
                {
                    Log.Information("Circuit breaker cerrado. Solicitudes normales reanudadas.");
                });
    }
}