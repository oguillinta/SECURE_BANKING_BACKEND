using ApiSecureBank.DTOs;
using ApiSecureBank.Repositories;
using AutoMapper;
using Microsoft.AspNetCore.Http.HttpResults;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

namespace ApiSecureBank.Endpoints
{
    public static class InterestRatesEndpoint
    {
        private readonly static string container = "interestRates";

        public static RouteGroupBuilder MapInterestRates(this RouteGroupBuilder group)
        {
            group.MapGet("/", GetAll)
                .CacheOutput(c => c.Expire(TimeSpan.FromSeconds(60)).Tag("interestrates-get"));
            return group;
        }

        static async Task<Results<Ok<List<InterestRateDTO>>, NotFound>> GetAll(IInterestRatesRepository repository, IMapper mapper)
        {
            var interestRates = await repository.GetAll();
            var interestRatesDTO = mapper.Map<List<InterestRateDTO>>(interestRates);
            return TypedResults.Ok(interestRatesDTO);
        }
    }
}