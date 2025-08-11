using ApiSecureBank.DBContext;
using ApiSecureBank.Entities;
using Microsoft.EntityFrameworkCore;

namespace ApiSecureBank.Repositories
{
    public class InterestRatesRepository(ApplicationDBContext context,
        IHttpContextAccessor httpContextAccessor) : IInterestRatesRepository
    {
        public async Task<List<InterestRate>> GetAll()
        {
            return await context.InterestRates.OrderBy(g => g.productName).ToListAsync();
        }

        public async Task<int> Create(InterestRate interestRate)
        {
            context.Add(interestRate);
            await context.SaveChangesAsync();
            return interestRate.Id;
        }
        // Example method to get an InterestRate by ID
        public async Task<InterestRate?> GetById(int id)
        {
            return await context.InterestRates.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
        }

        public async Task<List<InterestRate>> GetByName(string name)
        {
            return await context.InterestRates.Where(g => g.productName.Contains(name))
                .OrderBy(g => g.productName)
                .ToListAsync();
        }
        // Example method to get all InterestRates


        // Example method to check if a InterestRate exists by ID
        public async Task<bool> Exist(int id)
        {
            return await context.InterestRates.AnyAsync(g => g.Id == id);
        }
        // Example method to update an InterestRate
        public async Task Update(InterestRate interestRate)
        {
            context.Update(interestRate);
            await context.SaveChangesAsync();
        }
        // Example method to delete an InterestRate
        public async Task Delete(int id)
        {
            await context.InterestRates
                .Where(g => g.Id == id)
                .ExecuteDeleteAsync();
        }
    }
}
