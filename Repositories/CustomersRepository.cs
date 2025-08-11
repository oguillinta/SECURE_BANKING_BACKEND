using ApiSecureBank.DBContext;
using ApiSecureBank.Entities;
using Microsoft.EntityFrameworkCore;

namespace ApiSecureBank.Repositories
{
    public class CustomersRepository(ApplicationDBContext context,
        IHttpContextAccessor httpContextAccessor) : ICustomersRepository
    {
        public async Task<List<Customer>> GetAll()
        {
            return await context.Customers.OrderBy(g => g.firstName).ToListAsync();
        }

        public async Task<int> Create(Customer customer)
        {
            context.Add(customer);
            await context.SaveChangesAsync();
            return customer.Id;
        }
        // Example method to get an Customer by ID
        public async Task<Customer?> GetById(int id)
        {
            return await context.Customers.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
        }

        public async Task<List<Customer>> GetByLastName(string lastName)
        {
            return await context.Customers.Where(g => g.lastName.Contains(lastName))
                .OrderBy(g => g.firstName)
                .ToListAsync();
        }
        // Example method to get all Customers


        // Example method to check if a Customer exists by ID
        public async Task<bool> Exist(int id)
        {
            return await context.Customers.AnyAsync(g => g.Id == id);
        }
        // Example method to update an Customer
        public async Task Update(Customer customer)
        {
            context.Update(customer);
            await context.SaveChangesAsync();
        }
        // Example method to delete an Customer
        public async Task Delete(int id)
        {
            await context.Customers
                .Where(g => g.Id == id)
                .ExecuteDeleteAsync();
        }
    }
}
