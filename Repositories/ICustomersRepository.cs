using ApiSecureBank.Entities;

namespace ApiSecureBank.Repositories
{
    public interface ICustomersRepository
    {
        Task<int> Create(Customer customer);
        Task Delete(int id);
        Task<bool> Exist(int id);
        Task<List<Customer>> GetAll();
        Task<Customer?> GetById(int id);
        Task<List<Customer>> GetByLastName(string lastName);
        Task Update(Customer customer);
    }
}