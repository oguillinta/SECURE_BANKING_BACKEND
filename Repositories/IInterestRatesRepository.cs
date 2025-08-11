using ApiSecureBank.Entities;

namespace ApiSecureBank.Repositories
{
    public interface IInterestRatesRepository
    {
        Task<List<InterestRate>> GetAll();
    }
}