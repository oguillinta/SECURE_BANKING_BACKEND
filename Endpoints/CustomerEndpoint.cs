using ApiSecureBank.DTOs;
using ApiSecureBank.Entities;
using ApiSecureBank.Repositories;
using AutoMapper;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.OutputCaching;

namespace ApiSecureBank.Endpoints
{
    public static class CustomerEndpoint
    {
        private readonly static string container = "customers";
        public static RouteGroupBuilder MapCustomers(this RouteGroupBuilder group)
        {
            group.MapGet("/", GetAll)
                .CacheOutput(c => c.Expire(TimeSpan.FromSeconds(60)).Tag("customers-get"));
            group.MapGet("/GetByLastName/{lastName}", GetByLastName)
                .CacheOutput(c => c.Expire(TimeSpan.FromSeconds(60)).Tag("customers-get"));
            group.MapGet("/{id:int}", GetById);
            group.MapPost("/", Create);
            group.MapPut("/{id:int}", Update);
            group.MapDelete("/{id:int}", Delete);
            return group;
        }


        static async Task<Results<Ok<List<CustomerDTO>>, NotFound>> GetAll(ICustomersRepository repository, IMapper mapper)
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            var customers = await repository.GetAll();
            var customersDTO = mapper.Map<List<CustomerDTO>>(customers);
            return TypedResults.Ok(customersDTO);
        }
        static async Task<Results<Ok<CustomerDTO>, NotFound>> GetById(int id,
            ICustomersRepository customersRepository,
            IMapper mapper)
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            var customer = await customersRepository.GetById(id);
            if (customer is null)
            {
                return TypedResults.NotFound();
            }
            var customerDTO = mapper.Map<CustomerDTO>(customer);
            return TypedResults.Ok(customerDTO);
        }
        static async Task<Ok<IEnumerable<CustomerDTO>>> GetByLastName(string lastName, ICustomersRepository repository, IMapper mapper)
        {
            var customers = await repository.GetByLastName(lastName);
            var customersDTO = mapper.Map<IEnumerable<CustomerDTO>>(customers);
            return TypedResults.Ok(customersDTO);
        }
        static async Task<Results<Created<CustomerDTO>, NotFound>> Create(
            CreateCustomerDTO createCustomerDTO,
            ICustomersRepository repository,
            ICustomersRepository customersRepository,
            IOutputCacheStore outputCacheStore,
            IMapper mapper)
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            var customer = mapper.Map<Customer>(createCustomerDTO);
            //customer.CustomerId = customerId;
            var id = await repository.Create(customer);
            await outputCacheStore.EvictByTagAsync("customers-get", default);
            var customerDTO = mapper.Map<CustomerDTO>(customer);
            return TypedResults.Created($"/typeCustomers/{id}", customerDTO);
        }

        static async Task<Results<NoContent, NotFound, BadRequest<string>>> Update(int id, CreateCustomerDTO createCustomerDTO,
            ICustomersRepository customerRepository, ICustomersRepository customersRepository, IOutputCacheStore outputCacheStore, IMapper mapper)
        {

            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            if (!await customerRepository.Exist(id))
            {
                return TypedResults.NotFound();
            }
            var customerForUpdate = mapper.Map<Customer>(createCustomerDTO);
            customerForUpdate.Id = id;
            //customerForUpdate.CustomerId = customerId;

            await customerRepository.Update(customerForUpdate);
            await outputCacheStore.EvictByTagAsync("customers-get", default);
            return TypedResults.NoContent();
        }

        static async Task<Results<NoContent, NotFound>> Delete(int id,
            ICustomersRepository customerRepository, ICustomersRepository customersRepository,
            IOutputCacheStore outputCacheStore)
        {
            //if (!await customersRepository.Exist(customerId))
            //{
            //    return TypedResults.NotFound();
            //}
            if (!await customerRepository.Exist(id))
            {
                return TypedResults.NotFound();
            }
            var customer = await customerRepository.GetById(id);
            await customerRepository.Delete(id);
            await outputCacheStore.EvictByTagAsync("customers-get", default);
            return TypedResults.NoContent();
        }
    }
}
