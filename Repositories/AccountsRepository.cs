using ApiSecureBank.DBContext;
using ApiSecureBank.Entities;
using Microsoft.EntityFrameworkCore;

namespace ApiSecureBank.Repositories
{
    public class AccountsRepository(ApplicationDBContext context,
        IHttpContextAccessor httpContextAccessor) : IAccountsRepository
    {
        public async Task<List<Account>> GetAll(int customerId)
        {
            return await context.Accounts.OrderBy(g => g.accountNumber).ToListAsync();
        }

        public async Task<int> Create(Account account)
        {
            context.Add(account);
            await context.SaveChangesAsync();
            return account.Id;
        }
        // Example method to get an Customer by ID
        public async Task<Account?> GetById(int id)
        {
            return await context.Accounts.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
        }

        public async Task<List<Account>> GetByNumber(string name)
        {
            return await context.Accounts.Where(g => g.accountNumber.Contains(name))
                .OrderBy(g => g.accountNumber)
                .ToListAsync();
        }
        // Example method to get all Customers


        // Example method to check if a Customer exists by ID
        public async Task<bool> Exist(int id)
        {
            return await context.Accounts.AnyAsync(g => g.Id == id);
        }
        // Example method to update an Customer
        public async Task Update(Account account)
        {
            context.Update(account);
            await context.SaveChangesAsync();
        }
        // Example method to delete an Customer
        public async Task Delete(int id)
        {
            await context.Accounts
                .Where(g => g.Id == id)
                .ExecuteDeleteAsync();
        }
    }
}
