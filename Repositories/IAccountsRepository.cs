using ApiSecureBank.Entities;

namespace ApiSecureBank.Repositories
{
    public interface IAccountsRepository
    {
        Task<int> Create(Account account);
        Task Delete(int id);
        Task<bool> Exist(int id);
        Task<List<Account>> GetAll(int customerId);
        Task<Account?> GetById(int id);
        Task<List<Account>> GetByNumber(string name);
        Task Update(Account account);
    }
}