using Microsoft.AspNetCore.Builder;
using Serilog;
using System;

// ------------------------------------------------------------------------------------
// Program.cs - Punto de entrada principal de la aplicacin ASP.NET Core
// Este archivo ahora solo contiene el flujo de inicio, delegando la configuracin
// de servicios y del pipeline a la clase AppConfigurator.
// ------------------------------------------------------------------------------------

try
{
    // Crear el constructor de la aplicacin
    var builder = WebApplication.CreateBuilder(args);

    // Configurar servicios utilizando el mtodo modular
    AppConfigurator.ConfigureServices(builder);

    // Construir la aplicacin
    var app = builder.Build();

    // Configurar el pipeline de solicitudes HTTP utilizando el mtodo modular
    AppConfigurator.ConfigurePipeline(app);

    // Iniciar la aplicacin
    app.Run();
}
catch (Exception ex)
{
    // Captura cualquier excepcin fatal durante el inicio de la aplicacin
    Log.Fatal(ex, "La aplicación fall al iniciar o durante la ejecucin.");
}
finally
{
    // Asegurarse de que el logger se cierre y vacíe
    Log.CloseAndFlush();
}