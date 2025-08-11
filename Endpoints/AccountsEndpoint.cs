//
// Archivo: AccountsEndpoint.cs
// Descripción: Endpoint para el manejo de cuentas, ahora con la lógica de protección de datos
// y las propiedades de la clase Account correctamente referenciadas.
//
using ApiSecureBank.DTOs;
using ApiSecureBank.Entities;
using ApiSecureBank.Repositories;
using ApiSecureBank.Services;
using AutoMapper;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc; // Se necesita este using para [FromServices]

namespace ApiSecureBank.Endpoints
{
    public static class AccountsEndpoint
    {
        private readonly static string container = "accounts";
        public static RouteGroupBuilder MapAccounts(this RouteGroupBuilder group)
        {
            group.MapGet("/", GetAllAccounts)
                 .CacheOutput(c => c.Expire(TimeSpan.FromSeconds(60)).Tag("accounts-get"));
            group.MapGet("/GetByNumber/{number}", GetByNumber)
                 .CacheOutput(c => c.Expire(TimeSpan.FromSeconds(60)).Tag("accounts-get"));
            group.MapGet("/{id:int}", GetById);
            group.MapPost("/", Create);
            group.MapPut("/{id:int}", Update);
            group.MapDelete("/{id:int}", Delete);
            return group;
        }

        static async Task<Results<Ok<List<AccountDTO>>, NotFound>> GetAllAccounts(IAccountsRepository repository,
            ICustomersRepository customersRepository, IMapper mapper)
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            var accounts = await repository.GetAll(1);
            var accountsDTO = mapper.Map<List<AccountDTO>>(accounts);
            return TypedResults.Ok(accountsDTO);
        }

        static async Task<Results<Ok<AccountDTO>, NotFound, ProblemHttpResult>> GetById(
            int id,
            IAccountsRepository accountsRepository,
            ICustomersRepository customersRepository,
            IMapper mapper,
            ISecureDataService secureDataService,
            [FromServices] ILogger logger) // Se ha corregido el parámetro del logger con [FromServices]
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            var account = await accountsRepository.GetById(id);
            if (account is null)
            {
                return TypedResults.NotFound();
            }

            string purpose = $"Account.AccountNumber_{account.Id}";

            try
            {
                logger.LogInformation("Protegiendo el numero de cuenta para el id: {AccountId}", account.Id);

                var protectedAccountNumber = secureDataService.ProtectSensitiveData(account.accountNumber, purpose);

                logger.LogInformation("Numero de cuenta protegido. Original: {OriginalLength}, Protegido: {ProtectedLength}",
                    account.accountNumber.Length, protectedAccountNumber.Length);

                var unprotectedAccountNumber = secureDataService.UnprotectSensitiveData<string>(protectedAccountNumber, purpose);

                if (account.accountNumber == unprotectedAccountNumber)
                {
                    logger.LogInformation("Proteccion y desproteccion exitosa. La integridad de los datos se mantiene.");
                    account.accountNumber = unprotectedAccountNumber;
                }
                else
                {
                    logger.LogError("Fallo en la verificacion de integridad de datos para el numero de cuenta.");
                    return TypedResults.Problem("Error: Fallo la verificacion de integridad del numero de cuenta", statusCode: 500);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Ocurrio un error al intentar proteger/desproteger datos sensibles del numero de cuenta.");
                return TypedResults.Problem($"Error inesperado: {ex.Message}", statusCode: 500);
            }

            var accountDTO = mapper.Map<AccountDTO>(account);
            return TypedResults.Ok(accountDTO);
        }

        static async Task<Ok<IEnumerable<AccountDTO>>> GetByNumber(string number, IAccountsRepository repository, IMapper mapper)
        {
            var accounts = await repository.GetByNumber(number);
            var accountsDTO = mapper.Map<IEnumerable<AccountDTO>>(accounts);
            return TypedResults.Ok(accountsDTO);
        }

        static async Task<Results<Created<AccountDTO>, NotFound>> Create(
            CreateAccountDTO createAccountDTO,
            IAccountsRepository repository,
            ICustomersRepository customersRepository,
            IOutputCacheStore outputCacheStore,
            IMapper mapper)
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            var account = mapper.Map<Account>(createAccountDTO);
            //account.CustomerId = customerId;
            var id = await repository.Create(account);
            await outputCacheStore.EvictByTagAsync("accounts-get", default);
            var accountDTO = mapper.Map<AccountDTO>(account);
            return TypedResults.Created($"/typeAccounts/{id}", accountDTO);
        }

        static async Task<Results<NoContent, NotFound, BadRequest<string>>> Update(int id, CreateAccountDTO createAccountDTO,
            IAccountsRepository accountRepository, ICustomersRepository customersRepository, IOutputCacheStore outputCacheStore, IMapper mapper)
        {

            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            if (!await accountRepository.Exist(id))
            {
                return TypedResults.NotFound();
            }
            var accountForUpdate = mapper.Map<Account>(createAccountDTO);
            accountForUpdate.Id = id;
            //  accountForUpdate.customerId = customerId;

            await accountRepository.Update(accountForUpdate);
            await outputCacheStore.EvictByTagAsync("accounts-get", default);
            return TypedResults.NoContent();
        }

        static async Task<Results<NoContent, NotFound>> Delete(int id,
            IAccountsRepository accountRepository, ICustomersRepository customersRepository,
            IOutputCacheStore outputCacheStore)
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            if (!await accountRepository.Exist(id))
            {
                return TypedResults.NotFound();
            }
            var account = await accountRepository.GetById(id);
            await accountRepository.Delete(id);
            await outputCacheStore.EvictByTagAsync("accounts-get", default);
            return TypedResults.NoContent();
        }
    }
}