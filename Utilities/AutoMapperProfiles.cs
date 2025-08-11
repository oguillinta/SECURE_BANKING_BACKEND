using ApiSecureBank.DTOs;
using ApiSecureBank.Entities;
using AutoMapper;

namespace ApiSecureBank.Utilities
{
    public class AutoMapperProfiles : Profile
    {
        public AutoMapperProfiles()
        {
            CreateMap<Account, AccountDTO>();
            CreateMap<CreateAccountDTO, Account>();
            CreateMap<Customer, CustomerDTO>();
            CreateMap<CreateCustomerDTO, Customer>();
            CreateMap<InterestRate, InterestRateDTO>();
            CreateMap<AccountSummaryReport, AccountSummaryReportDTO>();
            CreateMap<CreateAccountSummaryReportDTO, AccountSummaryReport>();
        }
    }
}
