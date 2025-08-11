
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace ApiSecureBank.Extensions;

public class ExceptionHandlingFilter : IEndpointFilter
{
    private readonly ILogger<ExceptionHandlingFilter> _logger;

    public ExceptionHandlingFilter(ILogger<ExceptionHandlingFilter> logger)
    {
        _logger = logger;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            return await next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ocurri&oacute; un error inesperado en el endpoint: {EndpointName}", context.HttpContext.Request.Path);
            return Results.Problem("Ocurri&oacute; un error interno.", statusCode: 500);
        }
    }
}